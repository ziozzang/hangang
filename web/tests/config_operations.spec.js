import { test, expect } from '@playwright/test';

const operation = (id, state = 'candidate_activated') => ({
  id, operation_id: id.toString(16).padStart(32, '0'), authority_id: 'b'.repeat(32),
  actor_kind: id % 2 ? 'account' : 'system', actor_user_id: id % 2 ? 7 : null,
  accepted_at_unix_ms: 1789000000000 + id * 1000,
  finished_at_unix_ms: ['accepted', 'indeterminate'].includes(state) ? null : 1789000001000 + id * 1000,
  expected_revision: id - 1, candidate_sha256: 'a'.repeat(64),
  store_kind: 'local_file', authority_epoch: null, state, release_state: 'not_applicable', release_id: null,
});

async function fixture(page, { locale = 'en', accounts = false, unavailable = false, delayed = false, delayedPrune = false, holdExportPage = false, changedHistory = false, invalid = false, longHistory = false, changedAuthority = false, historyGap = false, pruneConflict = false, noTerminal = false, v2Release = false, missingReleaseState = false, releaseStatus = 200, delayedRelease = false } = {}) {
  const calls = [];
  let pruned = false;
  let released = false;
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
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
    if (url.pathname === '/v1/config/operations') {
      if (delayed) await blocked;
      if (unavailable) return route.fulfill({ status: 503, json: { title: 'Unavailable', detail: 'history unavailable' } });
      if (request.headers().authorization === 'Bearer viewer-session') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      const after = Number(url.searchParams.get('after'));
      if (holdExportPage && after === 100) await blocked;
      const authorityId = changedAuthority && after ? 'c'.repeat(32) : 'b'.repeat(32);
      const rows = pruned ? [operation(1, 'accepted'), operation(101, 'indeterminate')].filter((record) => record.id > after)
        : longHistory ? Array.from({ length: 100 }, (_, index) => operation(after + index + 1))
        : after ? [operation(101, 'indeterminate')] : Array.from({ length: 100 }, (_, index) =>
          operation(index + 1, noTerminal ? 'accepted' : index === 0 ? 'accepted' : index === 1 ? 'failed' : 'candidate_activated'));
      if (v2Release) for (const record of rows.filter((record) => record.id === 3 || record.id === 4)) {
        if (noTerminal && record.id === 3) { record.state = 'candidate_activated'; record.finished_at_unix_ms = record.accepted_at_unix_ms + 1000; }
        record.receipt_version = 2; record.store_kind = 'shared_store'; record.authority_epoch = 'c'.repeat(32);
        record.operation_id = record.id.toString(16).padStart(16, '0') + 'd'.repeat(16);
        record.release_state = released ? 'acknowledged' : record.id === 3 ? 'protected' : 'pending';
        record.release_id = released ? 'e'.repeat(32) : record.id === 4 ? 'f'.repeat(32) : null;
        if (missingReleaseState && record.id === 3) { delete record.release_state; delete record.release_id; }
      }
      if (historyGap && !after) rows.shift();
      for (const record of rows) record.authority_id = authorityId;
      const data = { scope: 'instance', coverage: ['acceptance', 'local_outcome'], authority_id: authorityId,
        started_at_unix_ms: 1788999999000, oldest_id: historyGap ? 2 : 1, latest_id: longHistory ? 10000 : 101, records: rows,
        next_after: rows.at(-1)?.id ?? after, has_more: pruned ? false : longHistory ? after < 9900 : after === 0,
        history_revision: pruned || released || changedHistory && after ? 203 : 202, pruned_through: pruned ? 100 : historyGap ? 1 : 0,
        truncated: pruned || historyGap,
        capacity: 10000, stored_records: pruned ? 2 : historyGap ? 100 : longHistory ? 10000 : 101,
        writes_available: !longHistory, server_time_unix_ms: 1789001000000 };
      if (invalid) delete data.writes_available;
      return route.fulfill({ json: data });
    }
    if (url.pathname === '/v1/config/operations/release') {
      if (delayedRelease) await blocked;
      if (releaseStatus !== 200) return route.fulfill({ status: releaseStatus, json: { title: 'Release unavailable', detail: 'check outcome' } });
      released = true;
      return route.fulfill({ json: { scope: 'instance', operation_id: request.postDataJSON().operation_id,
        release_id: 'e'.repeat(32), release_state: 'acknowledged' } });
    }
    if (url.pathname === '/v1/config/operations/prune') {
      if (delayedPrune) await blocked;
      if (request.headers().authorization === 'Bearer viewer-session') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      if (pruneConflict) return route.fulfill({ status: 409, json: { title: 'Conflict', detail: 'history changed' } });
      pruned = true;
      return route.fulfill({ json: { pruned_records: 99, retained_unresolved: 2,
        record: { id: 102, action: 'config_operations_prune', through_id: 100 } } });
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

test('export all collects the complete stable retained revision before starting one download', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#config-operations-export-all').click();
  const download = await downloadPromise;
  const contents = await (await import('node:fs/promises')).readFile(await download.path(), 'utf8');
  const exported = JSON.parse(contents);
  expect(exported.export_scope).toBe('all_retained_at_history_revision');
  expect(exported.history_revision).toBe(202);
  expect(exported.page_count).toBe(2);
  expect(exported.records).toHaveLength(101);
  expect(exported.records.at(-1).id).toBe(101);
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  expect(calls.filter((call) => call.path === '/v1/config/operations').map((call) => call.search)).toEqual([
    '?after=0&limit=100', '?after=0&limit=100', '?after=100&limit=100',
  ]);
});

test('mutation between export pages aborts without downloading a partial archive', async ({ page }) => {
  const downloads = []; page.on('download', (download) => downloads.push(download));
  await fixture(page, { changedHistory: true });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-export-all').click();
  await expect(page.locator('#config-operations-message')).toContainText('No file was downloaded');
  expect(downloads).toHaveLength(0);
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
});

test('logout while an export page is held starts no download and scrubs the page', async ({ page }) => {
  const downloads = []; page.on('download', (download) => downloads.push(download));
  const { calls, release } = await fixture(page, { holdExportPage: true });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-export-all').click();
  await expect.poll(() => calls.filter((call) => call.path === '/v1/config/operations').some((call) => call.search === '?after=100&limit=100')).toBe(true);
  await expect(page.locator('#config-operations-export-all')).toBeDisabled();
  await expect(page.locator('#config-operations-prune')).toBeDisabled();
  await expect(page.locator('#config-operations-export-all')).toContainText('100/101');
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
  await expect(page.locator('#config-operations-export-all')).toBeDisabled();
  expect(downloads).toHaveLength(0);
});

test('export all is bounded to exactly 10,000 retained records and 100 pages', async ({ page }) => {
  test.setTimeout(60000);
  const { calls } = await fixture(page, { longHistory: true });
  await page.locator('[data-view="config-operations"]').click();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#config-operations-export-all').click();
  const download = await downloadPromise;
  const contents = await (await import('node:fs/promises')).readFile(await download.path(), 'utf8');
  const exported = JSON.parse(contents);
  expect(exported.records).toHaveLength(10000);
  expect(exported.page_count).toBe(100);
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(101);
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

test('sparse retained history discloses pruning and remains pageable', async ({ page }) => {
  await fixture(page, { historyGap: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-message')).toContainText('not complete history');
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(99);
  await expect(page.locator('#config-operations-meta')).toContainText('Pruned through: 1');
});

test('terminal pruning requires confirmation, exact history CAS, and never retries a conflict', async ({ page }) => {
  const { calls } = await fixture(page, { pruneConflict: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-prune')).toBeEnabled();
  await page.locator('#config-operations-prune').click();
  await expect(page.locator('#confirm-message')).toContainText('including earlier pages');
  await expect(page.locator('#confirm-message')).toContainText('V2 receipts without acknowledged release are retained');
  await page.locator('#confirm-dialog [value="cancel"]').click();
  expect(calls.filter((call) => call.path.endsWith('/prune'))).toHaveLength(0);
  await page.locator('#config-operations-prune').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-message')).toContainText('No automatic retry');
  const prunes = calls.filter((call) => call.path.endsWith('/prune'));
  expect(prunes).toHaveLength(1);
  expect(prunes[0].body).toEqual({ through_id: 100, expected_latest_id: 101, expected_history_revision: 202 });
  expect(prunes[0].authorization).toBe('Bearer fixture-admin-token');
});

test('successful pruning keeps unresolved records visible and discloses a sparse history', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-prune').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(2);
  await expect(page.locator('#config-operations-rows')).toContainText('outcome not yet recorded');
  await expect(page.locator('#config-operations-rows')).toContainText('outcome unknown');
  await expect(page.locator('#config-operations-message')).toContainText('not complete history');
  await expect(page.locator('#config-operations-prune')).toBeDisabled();
  expect(calls.filter((call) => call.path.endsWith('/prune'))).toHaveLength(1);
});

test('full history still permits explicit terminal pruning but unresolved-only pages do not', async ({ page }) => {
  await fixture(page, { longHistory: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-meta')).toContainText('10,000/10,000');
  await expect(page.locator('#config-operations-prune')).toBeEnabled();
});

test('unresolved-only page does not offer terminal pruning', async ({ page }) => {
  await fixture(page, { noTerminal: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-prune')).toBeDisabled();
});

test('a pruning response arriving after logout cannot restore privileged history', async ({ page }) => {
  const { calls, release } = await fixture(page, { delayedPrune: true });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-prune').click();
  await page.locator('#confirm-accept').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operations/prune')).toBe(true);
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
  await expect(page.locator('#config-operations-export')).toBeDisabled();
  await expect(page.locator('#config-operations-prune')).toBeDisabled();
});

test('a changed authority between pages requires a fresh first-page read', async ({ page }) => {
  await fixture(page, { changedAuthority: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  await page.locator('#config-operations-next').click();
  await expect(page.locator('#config-operations-message')).toContainText('authority or history changed');
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
  await expect(page.locator('#config-operations-export')).toBeDisabled();
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
  await expect(page.locator('#config-operations-meta')).toContainText('접수, 이 인스턴스의 결과');
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('최종 결과 미기록');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('outcome not yet recorded');
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(1);
});

test('all 10,000 retained operations remain reachable beyond the recent backcursor stack', async ({ page }) => {
  test.setTimeout(60000);
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

test('V2 protection release is explicit, acknowledged, and separate from SQL receipt deletion', async ({ page }) => {
  const { calls } = await fixture(page, { v2Release: true });
  await page.locator('[data-view="config-operations"]').click();
  const row = page.locator('#config-operations-rows tr').nth(2);
  await expect(row).toContainText('SQL receipt protected');
  await row.getByRole('button', { name: 'Release SQL receipt protection' }).click();
  await expect(page.locator('#confirm-message')).toContainText('does not delete a SQL receipt');
  await page.locator('#confirm-dialog [value="cancel"]').click();
  expect(calls.filter((call) => call.path === '/v1/config/operations/release')).toHaveLength(0);
  await row.getByRole('button', { name: 'Release SQL receipt protection' }).click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-rows tr').nth(2)).toContainText('SQL release acknowledged');
  const releases = calls.filter((call) => call.path === '/v1/config/operations/release');
  expect(releases).toHaveLength(1);
  expect(releases[0].body).toEqual({ operation_id: '0000000000000003dddddddddddddddd' });
  await expect(page.locator('#config-operations-message')).not.toContainText('SQL receipt deleted');
});

test('V2 missing release state stays protected and is not eligible for local pruning', async ({ page }) => {
  await fixture(page, { v2Release: true, noTerminal: true, missingReleaseState: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-rows tr').nth(2)).toContainText('protection retained');
  await expect(page.locator('#config-operations-rows tr').nth(2).getByRole('button')).toHaveCount(0);
  await expect(page.locator('#config-operations-prune')).toBeDisabled();
  await expect(page.locator('#config-operations-rows tr').nth(3)).toContainText('Release pending');
  await expect(page.locator('#config-operations-rows tr').nth(3)).toContainText('Release ID:');
});

test('503 release outcome refreshes history without replaying mutation', async ({ page }) => {
  const { calls } = await fixture(page, { v2Release: true, releaseStatus: 503 });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-rows tr').nth(2).getByRole('button').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-message')).toContainText('no automatic mutation retry');
  expect(calls.filter((call) => call.path === '/v1/config/operations/release')).toHaveLength(1);
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(2);
});

test('unsupported release is visible without claiming an acknowledged release', async ({ page }) => {
  await fixture(page, { v2Release: true, releaseStatus: 501 });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-rows tr').nth(2).getByRole('button').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-message')).toContainText('does not support SQL receipt release');
  await expect(page.locator('#config-operations-rows tr').nth(2)).toContainText('SQL receipt protected');
});

for (const releaseStatus of [401, 403]) test(`release ${releaseStatus} withdraws privileged history`, async ({ page }) => {
  const { calls } = await fixture(page, { accounts: true, v2Release: true, releaseStatus });
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-operations-rows tr').nth(2).getByRole('button').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
  await expect(page.locator('[data-view="config-operations"]')).toBeHidden();
  expect(calls.filter((call) => call.path === '/v1/config/operations/release')).toHaveLength(1);
});

test('Korean release confirmation and late response after logout do not restore privileged rows', async ({ page }) => {
  const { calls, release } = await fixture(page, { locale: 'ko', accounts: true, v2Release: true, delayedRelease: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-rows tr').nth(2)).toContainText('SQL 영수증 보호 중');
  await page.locator('#config-operations-rows tr').nth(2).getByRole('button').click();
  await expect(page.locator('#confirm-message')).toContainText('SQL 영수증이나 보관 증거를 삭제하지 않으며');
  await page.locator('#confirm-accept').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operations/release')).toBe(true);
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
});
