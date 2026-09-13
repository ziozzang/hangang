import { test, expect } from '@playwright/test';

const hex = (character, count) => character.repeat(count);
const emptyHistory = { scope: 'instance', coverage: ['acceptance', 'local_outcome'],
  authority_id: hex('b', 32), started_at_unix_ms: 1788999999000,
  records: [], next_after: 0, oldest_id: null, latest_id: 0, history_revision: 0,
  pruned_through: 0, truncated: false, stored_records: 0, capacity: 10000,
  writes_available: true, server_time_unix_ms: 1789000001000, has_more: false };
const currentProof = { scope: 'configuration_authority', supported: true,
  proof: { epoch: hex('a', 32), revision: 17,
    stamp: { authority_id: hex('c', 32), operation_id: hex('d', 32), candidate_sha256: hex('e', 64) } },
  server_time_unix_ms: 1789000002000 };

async function fixture(page, { proofMode = 'present', holdProof = false, holdHistory = false, locale = 'en', accounts = false } = {}) {
  const calls = [];
  let releaseProof; let releaseHistory;
  const proofGate = new Promise((resolve) => { releaseProof = resolve; });
  const historyGate = new Promise((resolve) => { releaseHistory = resolve; });
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, authorization: request.headers().authorization });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(accounts ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') {
      const username = request.postDataJSON().username;
      return route.fulfill({ json: { token: `${username}-session`, user: { id: 2, username, role: username === 'viewer' ? 'viewer' : 'admin', enabled: true } } });
    }
    if (url.pathname === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (url.pathname === '/v1/config/operations') {
      if (holdHistory) await historyGate;
      return route.fulfill({ json: emptyHistory });
    }
    if (url.pathname === '/v1/config/operation-proof') {
      if (holdProof) await proofGate;
      if (proofMode === 'error') return route.fulfill({ status: 503, json: { title: 'Unavailable', detail: 'proof unavailable' } });
      if (proofMode === 'invalid') return route.fulfill({ json: { ...currentProof, proof: { ...currentProof.proof, epoch: 'bad' } } });
      if (proofMode === 'null') return route.fulfill({ json: { ...currentProof, proof: null } });
      if (proofMode === 'unsupported') return route.fulfill({ json: { ...currentProof, supported: false, proof: null } });
      return route.fulfill({ json: currentProof });
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
  return { calls, releaseProof, releaseHistory };
}

test('SQL-style current proof shows exact store identity without inferring local or fleet activation', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-fields')).toContainText(hex('a', 32));
  await expect(page.locator('#config-proof-fields')).toContainText('17');
  await expect(page.locator('#config-proof-fields')).toContainText(hex('c', 32));
  await expect(page.locator('#config-proof-fields')).toContainText(hex('d', 32));
  await expect(page.locator('#config-proof-fields')).toContainText(hex('e', 64));
  await expect(page.locator('#config-proof-state')).toContainText('does not prove local activation or fleet acknowledgement');
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
  expect(calls.filter((call) => call.path === '/v1/config/operation-proof')).toHaveLength(1);
  expect(calls.find((call) => call.path === '/v1/config/operation-proof').authorization).toBe('Bearer fixture-admin-token');
});

test('supported null proof is unknown rather than proof an operation never committed', async ({ page }) => {
  await fixture(page, { proofMode: 'null' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-state')).toContainText('does not prove the operation never committed');
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
});

test('unsupported store and failed proof request remain distinct from a null supported proof', async ({ page }) => {
  await fixture(page, { proofMode: 'unsupported' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-state')).toContainText('does not expose a current commit proof');
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
});

test('proof failure does not hide independently loaded local operation history', async ({ page }) => {
  await fixture(page, { proofMode: 'error' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-state')).toContainText('proof unavailable');
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
});

test('invalid proof metadata fails closed', async ({ page }) => {
  await fixture(page, { proofMode: 'invalid' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-state')).toContainText('proof unavailable');
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
});

test('proof can render while history is held, and late proof is scrubbed after logout', async ({ page }) => {
  const { calls, releaseProof, releaseHistory } = await fixture(page, { holdProof: true, holdHistory: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operation-proof')).toBe(true);
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operations')).toBe(true);
  releaseHistory();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
  await expect(page.locator('#config-proof-state')).toContainText('Checking');
  await page.locator('#logout-button').click();
  releaseProof();
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
  await expect(page.locator('#config-proof-state')).toBeEmpty();
});

test('Korean proof copy survives locale switching without matching another local authority', async ({ page }) => {
  await fixture(page, { locale: 'ko' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-state')).toContainText('로컬 활성화나 전체 인스턴스 승인');
  await expect(page.locator('#config-proof-fields')).toContainText(hex('c', 32));
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-proof-state')).toContainText('does not prove local activation');
});

test('manual proof refresh is independent of the history page', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-proof-fields')).toContainText(hex('a', 32));
  await page.locator('#config-proof-refresh').click();
  await expect.poll(() => calls.filter((call) => call.path === '/v1/config/operation-proof').length).toBe(2);
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(1);
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
});

test('leaving Change history scrubs an in-flight proof response', async ({ page }) => {
  const { calls, releaseProof } = await fixture(page, { holdProof: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operation-proof')).toBe(true);
  await page.locator('[data-view="status"]').click();
  releaseProof();
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
  await expect(page.locator('#config-proof-state')).toBeEmpty();
});

test('viewer navigation cannot start a privileged proof read', async ({ page }) => {
  const { calls } = await fixture(page, { accounts: true });
  await expect(page.locator('[data-view="config-operations"]')).toBeHidden();
  await page.evaluate(() => { location.hash = '#config-operations'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter((call) => call.path === '/v1/config/operation-proof')).toHaveLength(0);
  await expect(page.locator('#config-proof-fields')).toBeEmpty();
});
