import { test, expect } from '@playwright/test';
import { mkdir } from 'node:fs/promises';

const TOKEN = 'fixture-admin-token';
const status = {
  revision: 7, http_routes: 1, tcp_routes: 1, uptime_seconds: 20,
  version: 'test', process_id: 42, state: { ready: true, draining: false },
  metrics: { requests_total: 0, errors_total: 0, active_connections: 0 },
};
const first =
  {
    protocol: 'http', route_id: 'api', backend_index: 0,
    address: '<img src=x onerror="window.__opsInjected=1">', match_host: '*.example.test', listen: null,
    balance_mode: 'least_connections', weight: 2, available: false,
    health_mode: 'active_passive', probe_observed: true, active_requests: 3,
    route_active_connections: null,
  };
const last = {
    protocol: 'tcp', route_id: 'socket', backend_index: 0,
    address: '192.0.2.10:443', match_host: null, listen: '0.0.0.0:443',
    balance_mode: 'round_robin', weight: 1, available: true,
    health_mode: 'unmonitored', probe_observed: null, active_requests: null,
    route_active_connections: 4,
  };
const rows = [first, ...Array.from({ length: 99 }, (_, index) => ({
  ...first, backend_index: index + 1, address: `http://192.0.2.${index + 1}:8080`,
})), last];

async function fixture(page, viewer = false, operationRows = rows) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, search: url.search, authorization: request.headers().authorization });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(viewer
      ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') return route.fulfill({ json: {
      token: 'fixture-viewer-session', user: { id: 2, username: 'viewer', role: 'viewer', enabled: true },
    } });
    if (url.pathname === '/v1/status') return route.fulfill({ json: status });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/operations') {
      const offset = Number(url.searchParams.get('offset'));
      const limit = Number(url.searchParams.get('limit'));
      return route.fulfill({ json: {
        revision: 7, instance_id: 'fixture-instance',
        capabilities: {
          docker_enabled: false, self_restart_enabled: true,
          signed_updates_enabled: false, configuration_source: 'shared',
        },
        total: operationRows.length, offset, limit, rows: operationRows.slice(offset, offset + limit),
      } });
    }
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'unavailable' });
    return route.fulfill({ status: 404, body: 'not found' });
  });
  await page.goto('/ui/');
  if (viewer) {
    await page.locator('#login-username').fill('viewer');
    await page.locator('#login-password').fill('viewer password');
    await page.getByRole('button', { name: 'Sign in' }).click();
  } else {
    await page.getByLabel('Administrator token').fill(TOKEN);
    await page.getByRole('button', { name: 'Connect' }).click();
  }
  await expect(page.locator('#login-dialog')).toBeHidden();
  return calls;
}

test('checking state comes only from the initial-check gate and differs from observed exclusion', async ({ page }) => {
  await fixture(page, false, [
    { ...first, route_id: 'pending', initial_check_pending: true, probe_observed: false },
    { ...first, route_id: 'later-failed', initial_check_pending: false, probe_observed: true },
  ]);
  await page.locator('a[href="#operations"]').click();
  const pending = page.locator('#operations-rows tr').filter({ hasText: 'pending' });
  const failed = page.locator('#operations-rows tr').filter({ hasText: 'later-failed' });
  await expect(pending).toContainText('Checking — waiting for healthy probes');
  await expect(failed).toContainText('Excluded after observed health evidence');
  await page.locator('#locale-select').selectOption('ko');
  await expect(pending).toContainText('검사 중 — 정상 프로브 대기');
  await expect(failed).toContainText('관찰된 상태 검사 결과에 따라 제외됨');
});

test('TCP health rows describe transport probes rather than application health', async ({ page }) => {
  await fixture(page, false, [
    { ...last, route_id: 'tcp-pending', health_mode: 'active_tcp', available: false,
      probe_observed: false, initial_check_pending: true },
    { ...last, route_id: 'tcp-failed', health_mode: 'active_tcp', available: false,
      probe_observed: true, initial_check_pending: false },
  ]);
  await page.locator('a[href="#operations"]').click();
  const pending = page.locator('#operations-rows tr').filter({ hasText: 'tcp-pending' });
  const failed = page.locator('#operations-rows tr').filter({ hasText: 'tcp-failed' });
  await expect(pending).toContainText('TCP connection checks');
  await expect(pending).toContainText('Checking — waiting for successful connection probes');
  await expect(failed).toContainText('Excluded after observed connection failures');
  await page.locator('#locale-select').selectOption('ko');
  await expect(pending).toContainText('TCP 연결 검사');
  await expect(pending).toContainText('검사 중 — 성공한 연결 프로브 대기');
  await expect(failed).toContainText('관찰된 연결 실패로 선택 제외');
});

test('named members show stable ID, configured address and effective weight in both languages', async ({ page }) => {
  await fixture(page, false, [{ ...first, member_id: 'blue-1', address: 'http://192.0.2.10:8080', weight: 7 }]);
  await page.locator('a[href="#operations"]').click();
  const row = page.locator('#operations-rows tr').first();
  await expect(row).toContainText('Member blue-1 · #1');
  await expect(row).toContainText('http://192.0.2.10:8080');
  await expect(row).toContainText('weight 7');
  await page.locator('#locale-select').selectOption('ko');
  await expect(row).toContainText('멤버 blue-1 · #1');
  await expect(row).toContainText('가중치 7');
});

test('operations view shows real local eligibility, bounded paging and escaped target addresses', async ({ page }) => {
  const calls = await fixture(page);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#view-operations')).toBeVisible();
  await expect(page.locator('#operations-rows tr')).toHaveCount(100);
  await expect(page.locator('#operations-rows')).toContainText('Excluded');
  await expect(page.locator('#operations-rows')).toContainText('Active + passive checks');
  await expect(page.locator('#operations-rows')).toContainText('3 active requests');
  await expect(page.locator('#operations-capabilities')).toContainText('does not enumerate fleet peers');
  await expect(page.locator('#operations-rows')).toContainText(rows[0].address);
  await expect(page.locator('#operations-rows img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__opsInjected)).toBeUndefined();
  expect(calls.find((call) => call.path === '/v1/operations')).toMatchObject({
    search: '?offset=0&limit=100', authorization: `Bearer ${TOKEN}`,
  });
  await page.locator('#operations-next').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(1);
  await expect(page.locator('#operations-rows')).toContainText('192.0.2.10:443');
  await expect(page.locator('#operations-rows')).toContainText('Route-wide, not per target');
  await expect(page.locator('#operations-rows')).toContainText('Unmonitored');
  await expect(page.locator('#operations-range')).toContainText('101–101 of 101');
  await page.locator('#operations-prev').click();
  await expect(page.locator('#operations-rows')).toContainText(rows[0].address);
  await page.locator('#operations-refresh').click();
  await expect.poll(() => calls.filter((call) => call.path === '/v1/operations').length).toBe(4);
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#operations-title')).toHaveText('운영');
  await expect(page.locator('#operations-rows')).toContainText('선택 제외');
  await expect(page.locator('#operations-rows')).toContainText('처리 중인 요청 3개');
  await expect(page.locator('#operations-rows')).toContainText(rows[0].address);
});

test('viewer cannot navigate to operations or request its administrator API', async ({ page }) => {
  const calls = await fixture(page, true);
  await expect(page.locator('a[href="#operations"]')).toBeHidden();
  await page.evaluate(() => { location.hash = '#operations'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter((call) => call.path === '/v1/operations')).toHaveLength(0);
});

test('an expired or downgraded account clears privileged operations before showing sign-in', async ({ page }) => {
  await fixture(page);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(100);
  await page.route('**/v1/operations?*', (route) => route.fulfill({ status: 403, json: { title: 'Forbidden' } }));
  await page.locator('#operations-refresh').click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  await expect(page.locator('#operations-capabilities')).toBeEmpty();
});

test('a delayed operations response cannot refill the table after logout', async ({ page }) => {
  await fixture(page);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(100);
  let release;
  let requested;
  const gate = new Promise((resolve) => { release = resolve; });
  const seen = new Promise((resolve) => { requested = resolve; });
  await page.route('**/v1/operations?*', async (route) => {
    requested();
    await gate;
    await route.fulfill({ json: {
      revision: 7, instance_id: 'fixture-instance',
      capabilities: { docker_enabled: true, self_restart_enabled: true,
        signed_updates_enabled: true, configuration_source: 'shared' },
      total: 1, offset: 0, limit: 100, rows: [last],
    } });
  });
  await page.locator('#operations-refresh').click();
  await seen;
  await page.locator('#logout-button').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  release();
  await page.waitForTimeout(100);
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  await expect(page.locator('#operations-capabilities')).toBeEmpty();
});

test('capture owned Korean operations layout', async ({ page }) => {
  test.skip(!process.env.HANGANG_CAPTURE_OPERATIONS, 'Opt-in visual fixture capture');
  await page.setViewportSize({ width: 1440, height: 900 });
  await fixture(page);
  const visualRows = [
    { ...first, address: 'http://192.0.2.10:8080', route_id: 'api-public', match_host: '*.example.test',
      available: true, active_requests: 2 },
    { ...first, address: 'https://api.internal.test:8443', route_id: 'api-private', match_host: 'api.example.test',
      health_mode: 'unmonitored', probe_observed: null, active_requests: null, weight: 1 },
    { ...last, address: '198.51.100.20:443', route_id: 'edge-tcp' },
  ];
  await page.route('**/v1/operations?*', (route) => route.fulfill({ json: {
    revision: 7, instance_id: 'fixture-instance',
    capabilities: { docker_enabled: true, self_restart_enabled: true,
      signed_updates_enabled: false, configuration_source: 'shared' },
    total: visualRows.length, offset: 0, limit: 100, rows: visualRows,
  } }));
  await page.locator('#locale-select').selectOption('ko');
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(3);
  // Wait for the view's 180 ms entrance animation before saving a shareable image.
  await page.waitForTimeout(250);
  await mkdir('../docs/images', { recursive: true });
  await page.screenshot({ path: '../docs/images/console-operations-ko.png' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '/tmp/hangang-operations-ko-mobile.png' });
  await page.locator('.operations-table-wrap').scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/hangang-operations-ko-mobile-table.png' });
  const dimensions = await page.evaluate(() => ({ viewport: innerWidth,
    document: document.documentElement.scrollWidth,
    tableViewport: document.querySelector('.operations-table-wrap').clientWidth,
    tableContent: document.querySelector('.operations-table-wrap').scrollWidth }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.tableContent).toBeGreaterThan(dimensions.tableViewport);
});
