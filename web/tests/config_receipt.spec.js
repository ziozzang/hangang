import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const authority = 'a'.repeat(32);
const operation = 'b'.repeat(32);
const v2Operation = `${(7).toString(16).padStart(16, '0')}${'b'.repeat(16)}`;
const receipt = { scope: 'configuration_authority', supported: true,
  receipt: { epoch: 'c'.repeat(32), revision: 17,
    stamp: { authority_id: authority, operation_id: operation, candidate_sha256: 'd'.repeat(64) } },
  stored_records: 2, capacity: 100000, writes_available: true, server_time_unix_ms: 1789000002000 };
const v2Receipt = { ...receipt,
  receipt: { ...receipt.receipt, stamp: { ...receipt.receipt.stamp, operation_id: v2Operation, acceptance_seq: 7 } },
  high_water: 9, registered_authorities: 2, authority_capacity: 4096 };
const emptyHistory = { scope: 'instance', coverage: ['acceptance', 'local_outcome'],
  authority_id: 'e'.repeat(32), started_at_unix_ms: 1788999999000,
  records: [], next_after: 0, oldest_id: null, latest_id: 0, history_revision: 0,
  pruned_through: 0, truncated: false, stored_records: 0, capacity: 10000,
  writes_available: true, server_time_unix_ms: 1789000001000, has_more: false };

async function fixture(page, { mode = 'present', v2Mode = 'present', hold = false, holdV2 = false,
  locale = 'en', accounts = false, history = emptyHistory } = {}) {
  const calls = [];
  let release; let releaseV2;
  const gate = new Promise((resolve) => { release = resolve; });
  const v2Gate = new Promise((resolve) => { releaseV2 = resolve; });
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
    if (url.pathname === '/v1/config/operations') return route.fulfill({ json: history });
    if (url.pathname === '/v1/config/operation-proof') return route.fulfill({ json: { scope: 'configuration_authority', supported: false, proof: null, server_time_unix_ms: 1789000002000 } });
    if (url.pathname === '/v1/config/commit-receipt-v2') {
      if (holdV2) await v2Gate;
      if (v2Mode === 'error') return route.fulfill({ status: 503, json: { title: 'Unavailable' } });
      if (v2Mode === 'missing') return route.fulfill({ json: { ...v2Receipt, receipt: null, high_water: 0 } });
      if (v2Mode === 'unsupported') return route.fulfill({ json: { ...v2Receipt, supported: false, receipt: null,
        high_water: null, registered_authorities: null, authority_capacity: null,
        stored_records: null, capacity: null, writes_available: null } });
      if (v2Mode === 'invalid') return route.fulfill({ json: { ...v2Receipt, receipt: { ...v2Receipt.receipt,
        stamp: { ...v2Receipt.receipt.stamp, acceptance_seq: 8 } } } });
      if (v2Mode === 'invalid-prefix') return route.fulfill({ json: { ...v2Receipt, receipt: { ...v2Receipt.receipt,
        stamp: { ...v2Receipt.receipt.stamp, operation_id: operation } } } });
      return route.fulfill({ json: v2Receipt });
    }
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
  return { calls, release, releaseV2 };
}

async function search(page) {
  await page.locator('#config-receipt-authority').fill(authority);
  await page.locator('#config-receipt-operation').fill(operation);
  await page.locator('#config-receipt-search').click();
}

async function searchV2(page, sequence = '7') {
  await page.locator('#config-receipt-mode').selectOption('v2');
  await page.locator('#config-receipt-authority').fill(authority);
  await page.locator('#config-receipt-sequence').fill(sequence);
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

test('V2 uses only the canonical acceptance sequence namespace and labels the high-water fence', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await searchV2(page);
  await expect(page.locator('#config-receipt-fields')).toContainText('Committed acceptance sequence');
  await expect(page.locator('#config-receipt-fields')).toContainText('7');
  await expect(page.locator('#config-receipt-state')).toContainText('Committed sequence high-water: #9');
  await expect(page.locator('#config-receipt-state')).toContainText('Registered authorities: 2/4,096');
  await expect(page.locator('#config-receipt-state')).toContainText('not proof of complete history or local activation');
  const v2 = calls.filter((call) => call.path === '/v1/config/commit-receipt-v2');
  expect(v2).toHaveLength(1);
  expect([...v2[0].query.entries()]).toEqual([['authority_id', authority], ['acceptance_seq', '7']]);
  expect(v2[0].authorization).toBe('Bearer fixture-admin-token');
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(0);
});

test('V2 rejects zero, leading zeros and unsafe sequence before request', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-receipt-mode').selectOption('v2');
  await page.locator('#config-receipt-authority').fill(authority);
  for (const bad of ['0', '007', '9007199254740992']) {
    await page.locator('#config-receipt-sequence').fill(bad);
    await page.locator('#config-receipt-form').evaluate((form) => form.requestSubmit());
    await expect(page.locator('#config-receipt-state')).toContainText('positive canonical safe acceptance sequence');
  }
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt-v2')).toHaveLength(0);
});

for (const [v2Mode, expected] of [
  ['missing', 'commit outcome is unknown'], ['unsupported', 'does not support historical SQL receipts'],
  ['invalid', 'receipt unavailable'], ['invalid-prefix', 'receipt unavailable'], ['error', 'receipt unavailable'],
]) test(`V2 ${v2Mode} stays distinct from historical commit evidence`, async ({ page }) => {
  await fixture(page, { v2Mode });
  await page.locator('[data-view="config-operations"]').click();
  await searchV2(page);
  await expect(page.locator('#config-receipt-state')).toContainText(expected);
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
  if (v2Mode === 'missing') await expect(page.locator('#config-receipt-state')).toContainText('high-water: #0');
});

test('switching receipt version while V1 response is pending cannot display V1 evidence in V2', async ({ page }) => {
  const { calls, release } = await fixture(page, { hold: true });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/commit-receipt')).toBe(true);
  await page.locator('#config-receipt-mode').selectOption('v2');
  release();
  await expect(page.locator('#config-receipt-operation')).toBeHidden();
  await expect(page.locator('#config-receipt-sequence')).toBeVisible();
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
  await expect(page.locator('#config-receipt-state')).toBeEmpty();
  await page.locator('#config-receipt-sequence').fill('7');
  await page.locator('#config-receipt-search').click();
  await expect(page.locator('#config-receipt-state')).toContainText('high-water: #9');
});

test('local journal labels explicit V1, V2 and missing-version legacy rows without mixing IDs', async ({ page }) => {
  const row = (id, receiptVersion) => ({ id,
    operation_id: receiptVersion === 2 ? `${id.toString(16).padStart(16, '0')}${'b'.repeat(16)}` : String(id).repeat(32),
    authority_id: emptyHistory.authority_id,
    actor_kind: 'system', actor_user_id: null, accepted_at_unix_ms: 1789000000000,
    expected_revision: id - 1, candidate_sha256: 'f'.repeat(64), store_kind: 'shared_store',
    authority_epoch: 'c'.repeat(32), state: 'accepted', finished_at_unix_ms: null,
    ...(receiptVersion === undefined ? {} : { receipt_version: receiptVersion }) });
  const history = { ...emptyHistory, records: [row(1, undefined), row(2, 1), row(3, 2)],
    next_after: 3, oldest_id: 1, latest_id: 3, history_revision: 3, stored_records: 3 };
  await fixture(page, { history });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-rows details')).toHaveCount(3);
  await page.locator('#config-operations-rows details').evaluateAll((details) => details.forEach((detail) => { detail.open = true; }));
  await expect(page.locator('#config-operations-rows')).toContainText('Legacy V1 receipt · version omitted by older server');
  await expect(page.locator('#config-operations-rows')).toContainText('Legacy V1 receipt');
  await expect(page.locator('#config-operations-rows')).toContainText('Sequenced V2 receipt · acceptance #3');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#config-operations-export').click();
  const download = await downloadPromise;
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(exported.records.map((record) => record.receipt_version)).toEqual([undefined, 1, 2]);
  expect(exported.receipt_version_compatibility).toBe('missing means legacy_v1');
});

for (const [label, invalid] of [
  ['operation ID', { operation_id: 'b'.repeat(32) }],
  ['store kind', { operation_id: `${(3).toString(16).padStart(16, '0')}${'b'.repeat(16)}`, store_kind: 'local_file' }],
]) test(`a V2 journal row with invalid ${label} is unavailable rather than presented as sequenced evidence`, async ({ page }) => {
  const record = { id: 3, operation_id: `${(3).toString(16).padStart(16, '0')}${'b'.repeat(16)}`,
    authority_id: emptyHistory.authority_id, receipt_version: 2,
    actor_kind: 'system', actor_user_id: null, accepted_at_unix_ms: 1789000000000,
    expected_revision: 2, candidate_sha256: 'f'.repeat(64), store_kind: 'shared_store',
    authority_epoch: 'c'.repeat(32), state: 'accepted', finished_at_unix_ms: null,
    ...invalid };
  const history = { ...emptyHistory, records: [record], next_after: 3, oldest_id: 3,
    latest_id: 3, history_revision: 3, stored_records: 1 };
  await fixture(page, { history });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-message')).toContainText('response is invalid');
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
});

test('Korean V2 copy rerenders without changing the namespace or numeric fence', async ({ page }) => {
  const { calls } = await fixture(page, { locale: 'ko' });
  await page.locator('[data-view="config-operations"]').click();
  await searchV2(page);
  await expect(page.locator('#config-receipt-state')).toContainText('커밋 순번 상한');
  await expect(page.locator('#config-receipt-state')).toContainText('#9');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-receipt-state')).toContainText('Committed sequence high-water: #9');
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt-v2')).toHaveLength(1);
});
