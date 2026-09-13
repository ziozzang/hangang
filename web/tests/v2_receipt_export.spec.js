import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const authority = 'a'.repeat(32);
const snapshot = { high_water: 102, retention_generation: 4 };
const receipt = (sequence) => ({ epoch: 'c'.repeat(32), revision: sequence + 10,
  stamp: { authority_id: authority, acceptance_seq: sequence,
    operation_id: `${sequence.toString(16).padStart(16, '0')}${'b'.repeat(16)}`,
    candidate_sha256: 'd'.repeat(64) } });

async function fixture(page, { response = 'normal', hold = false, locale = 'en' } = {}) {
  const requests = [];
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    if (url.pathname === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (url.pathname === '/v1/status') return route.fulfill({ json: {
      revision: 1, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true },
    } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (url.pathname === '/v1/config/operations') return route.fulfill({ json: {
      scope: 'instance', authority_id: 'e'.repeat(32), coverage: ['acceptance', 'local_outcome'],
      started_at_unix_ms: 1789000000000, latest_id: 0, oldest_id: null, next_after: 0,
      history_revision: 0, pruned_through: 0, truncated: false, records: [], has_more: false,
      stored_records: 0, capacity: 10000, writes_available: true, server_time_unix_ms: 1789000002000,
    } });
    if (url.pathname === '/v1/config/operation-proof') return route.fulfill({ json: {
      scope: 'configuration_authority', supported: false, proof: null, server_time_unix_ms: 1789000002000,
    } });
    if (url.pathname === '/v1/config/commit-receipts-v2') {
      requests.push({ query: url.searchParams, authorization: request.headers().authorization });
      const after = Number(url.searchParams.get('after_seq'));
      if (hold && after === 100) await barrier;
      if (response === 'unsupported') return route.fulfill({ json: {
        scope: 'configuration_authority', supported: false, authority_id: authority, receipts: [],
        snapshot: null, next_after: null, has_more: null, server_time_unix_ms: 1789000002000,
      } });
      if (response === 'changed' && after === 100) return route.fulfill({ status: 409,
        json: { title: 'Receipt Snapshot Changed' } });
      if (response === 'tail-changed' && after === 102) return route.fulfill({ status: 409,
        json: { title: 'Receipt Snapshot Changed' } });
      if (response === 'full-cap' || response === 'over-cap') {
        const highWater = response === 'full-cap' ? 100000 : 100001;
        const records = after >= 100000 ? [] : Array.from({ length: 100 }, (_, index) => receipt(after + index + 1));
        return route.fulfill({ json: { scope: 'configuration_authority', supported: true,
          authority_id: authority, receipts: records,
          snapshot: { high_water: highWater, retention_generation: 4 },
          next_after: records.at(-1)?.stamp.acceptance_seq ?? after,
          has_more: after + records.length < highWater,
          server_time_unix_ms: 1789000002000,
        } });
      }
      const records = after === 0 ? Array.from({ length: 100 }, (_, index) => receipt(index + 1))
        : after === 100 ? [receipt(101), receipt(102)] : [];
      const broken = response === 'invalid-prefix' && after === 100;
      if (broken) records[0].stamp.operation_id = 'f'.repeat(32);
      if (response === 'duplicate' && after === 100) records[0] = receipt(100);
      if (response === 'out-of-order' && after === 100) records.reverse();
      if (response === 'leaked-new-commit' && after === 100) records.push(receipt(103));
      return route.fulfill({ json: {
        scope: 'configuration_authority', supported: true, authority_id: authority,
        receipts: records, snapshot: response === 'changed-metadata' && after === 100
          ? { ...snapshot, retention_generation: 5 } : snapshot,
        next_after: records.at(-1)?.stamp.acceptance_seq ?? after, has_more: after === 0,
        server_time_unix_ms: 1789000002000,
      } });
    }
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-receipt-mode').selectOption('v2');
  await page.locator('#config-receipt-authority').fill(authority);
  await expect(page.locator('#config-receipt-export-v2')).toBeEnabled();
  return { requests, release };
}

test('exports a pinned retained V2 SQL receipt set only after the empty tail probe', async ({ page }) => {
  const { requests } = await fixture(page);
  const downloadReady = page.waitForEvent('download');
  await page.locator('#config-receipt-export-v2').click();
  const download = await downloadReady;
  const archive = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(archive.export_scope).toBe('retained_v2_sql_commit_receipts_at_pinned_snapshot');
  expect(archive.snapshot).toEqual(snapshot);
  expect(archive.retained_receipt_count).toBe(102);
  expect(archive.receipts.map((entry) => entry.stamp.acceptance_seq)).toEqual(Array.from({ length: 102 }, (_, index) => index + 1));
  expect(archive.evidence_limit).toContain('no proof of current configuration');
  expect(requests.map((item) => item.query.get('after_seq'))).toEqual(['0', '100', '102']);
  expect(requests[0].query.has('snapshot_high_water')).toBe(false);
  for (const item of requests.slice(1)) {
    expect(item.query.get('snapshot_high_water')).toBe('102');
    expect(item.query.get('retention_generation')).toBe('4');
    expect(item.authorization).toBe('Bearer fixture-admin-token');
  }
  expect(requests[2].query.get('limit')).toBe('1');
  await expect(page.locator('#config-receipt-export-state')).toContainText('download started');
});

for (const response of ['changed', 'tail-changed', 'changed-metadata', 'invalid-prefix',
  'duplicate', 'out-of-order', 'leaked-new-commit', 'unsupported']) {
  test(`${response} retained V2 export produces no partial download`, async ({ page }) => {
    const { requests } = await fixture(page, { response });
    let downloads = 0;
    page.on('download', () => { downloads += 1; });
    await page.locator('#config-receipt-export-v2').click();
    await expect(page.locator('#config-receipt-export-state')).toContainText(
      response === 'unsupported' ? 'does not support' : response === 'changed' || response === 'tail-changed' ? 'snapshot changed' :
        'response is invalid');
    expect(downloads).toBe(0);
    expect(requests.length).toBe(response === 'unsupported' ? 1 : response === 'tail-changed' ? 3 : 2);
  });
}

test('logout during a held continuation prevents a late V2 receipt download', async ({ page }) => {
  const { requests, release } = await fixture(page, { hold: true });
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await page.locator('#config-receipt-export-v2').click();
  await expect.poll(() => requests.length).toBe(2);
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#config-receipt-authority')).toHaveValue('');
  await expect(page.locator('#config-receipt-export-state')).toBeEmpty();
  expect(downloads).toBe(0);
});

test('changing V2 query during a held continuation invalidates export without a file', async ({ page }) => {
  const { requests, release } = await fixture(page, { hold: true });
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await page.locator('#config-receipt-export-v2').click();
  await expect.poll(() => requests.length).toBe(2);
  await page.locator('#config-receipt-authority').fill('f'.repeat(32));
  release();
  await expect(page.locator('#config-receipt-export-state')).toBeEmpty();
  expect(downloads).toBe(0);
});

test('switching receipt versions during a held continuation invalidates export without a file', async ({ page }) => {
  const { requests, release } = await fixture(page, { hold: true });
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await page.locator('#config-receipt-export-v2').click();
  await expect.poll(() => requests.length).toBe(2);
  await page.locator('#config-receipt-mode').selectOption('v1');
  release();
  await expect(page.locator('#config-receipt-export-v2')).toBeHidden();
  expect(downloads).toBe(0);
});

test('navigation during a held continuation invalidates export without a file', async ({ page }) => {
  const { requests, release } = await fixture(page, { hold: true });
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await page.locator('#config-receipt-export-v2').click();
  await expect.poll(() => requests.length).toBe(2);
  await page.locator('[data-view="status"]').click();
  release();
  await expect(page.locator('#config-receipt-authority')).toHaveValue('');
  expect(downloads).toBe(0);
});

test('Korean V2 export copy updates without changing query or fetching receipts', async ({ page }) => {
  const { requests } = await fixture(page, { locale: 'ko' });
  await expect(page.locator('#config-receipt-export-v2')).toHaveText('보존된 V2 영수증 JSON 내보내기');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-receipt-export-v2')).toHaveText('Export retained V2 receipts JSON');
  expect(requests).toHaveLength(0);
});

test('exactly 100,000 retained V2 receipts can reach the 1,000-page export bound', async ({ page }) => {
  const { requests } = await fixture(page, { response: 'full-cap' });
  const downloadReady = page.waitForEvent('download');
  await page.locator('#config-receipt-export-v2').click();
  const download = await downloadReady;
  expect(download.suggestedFilename()).toContain('100000-4.json');
  expect(requests).toHaveLength(1001); // 1,000 pages and the empty tail probe.
});

test('a nonterminal 1,000th page rejects export beyond the page bound', async ({ page }) => {
  const { requests } = await fixture(page, { response: 'over-cap' });
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await page.locator('#config-receipt-export-v2').click();
  await expect(page.locator('#config-receipt-export-state')).toContainText('incomplete');
  expect(requests).toHaveLength(1000);
  expect(downloads).toBe(0);
});
