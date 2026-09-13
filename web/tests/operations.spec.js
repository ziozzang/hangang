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

async function fixture(page, viewer = false, operationRows = rows, retiredRows = []) {
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
    if (url.pathname === '/v1/retired-members') {
      const offset = Number(url.searchParams.get('offset'));
      const limit = Number(url.searchParams.get('limit'));
      return route.fulfill({ json: {
        total: retiredRows.length, offset, limit, capacity: 4096,
        rows: retiredRows.slice(offset, offset + limit),
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

test('desired state, admission gate and live leases remain distinct for HTTP and TCP', async ({ page }) => {
  await fixture(page, false, [
    { ...first, route_id: 'http-drain', member_id: 'blue', desired_state: 'draining', admission_open: false, active_admissions: 2, active_requests: 2 },
    { ...last, route_id: 'tcp-maint', member_id: 'green', desired_state: 'maintenance', admission_open: false, active_admissions: 3, member_active_streams: 2, health_mode: 'active_tcp', probe_observed: true },
    { ...last, route_id: 'unprobed', member_id: 'white', desired_state: 'maintenance', admission_open: false, active_admissions: 0 },
    { ...first, route_id: 'http-serving', member_id: 'orange', desired_state: 'serving', admission_open: true, active_admissions: 0, available: true },
  ]);
  await page.locator('a[href="#operations"]').click();
  const row = (id) => page.locator('#operations-rows tr').filter({ hasText: id });
  await expect(row('http-drain')).toContainText('Desired: Draining');
  await expect(row('http-drain')).toContainText('Admission closed');
  await expect(row('http-drain')).toContainText('2 active admission leases');
  await expect(row('tcp-maint')).toContainText('Desired: Maintenance');
  await expect(row('tcp-maint')).toContainText('3 active admission leases');
  await expect(row('tcp-maint')).toContainText('2 established member streams');
  await expect(row('tcp-maint')).toContainText('Probes suspended for maintenance');
  await expect(row('unprobed')).toContainText('No probes configured');
  await expect(row('tcp-maint')).toContainText('TCP member leases include pending dials');
  await expect(row('http-serving')).toContainText('Member gate open');
  await expect(row('http-serving')).toContainText('0 active admission leases');
  await expect(row('http-serving')).toContainText('Zero does not prove drain completion');
  await page.locator('#locale-select').selectOption('ko');
  await expect(row('http-drain')).toContainText('설정 상태: 드레이닝');
  await expect(row('tcp-maint')).toContainText('설정 상태: 유지보수');
  await expect(row('tcp-maint')).toContainText('진행 중인 admission lease 3개');
  await expect(row('http-serving')).toContainText('멤버 요청 게이트 열림');
});

test('older operations responses do not invent serving, an open gate or zero leases', async ({ page }) => {
  await fixture(page, false, [{ ...first, route_id: 'old-server', member_id: 'blue' }]);
  await page.locator('a[href="#operations"]').click();
  const row = page.locator('#operations-rows tr').first();
  await expect(row).toContainText('State unavailable');
  await expect(row).toContainText('Member gate state unavailable');
  await expect(row).toContainText('Admission count unavailable');
  await expect(row).not.toContainText('0 active admission leases');
  await page.locator('#locale-select').selectOption('ko');
  await expect(row).toContainText('멤버 요청 게이트 상태 확인 불가');
  await expect(row).toContainText('진행 중인 admission 수 확인 불가');
});

test('named TCP rows show established member streams separately from route connections in both languages', async ({ page }) => {
  await fixture(page, false, [{ ...last, route_id: 'tcp-streams', member_id: 'blue',
    member_active_streams: 3, route_active_connections: 7 }]);
  await page.locator('a[href="#operations"]').click();
  const row = page.locator('#operations-rows tr').first();
  await expect(row).toContainText('7 active route connections');
  await expect(row).toContainText('3 established member streams');
  await expect(row).toContainText('excludes pending dials');
  await expect(row).toContainText('Not a drain-complete signal');
  await expect(row).not.toContainText('active requests');
  await page.locator('#locale-select').selectOption('ko');
  await expect(row).toContainText('활성 라우트 연결 7개');
  await expect(row).toContainText('확립된 멤버 스트림 3개');
  await expect(row).toContainText('드레인 완료를 뜻하지 않습니다');
});

test('zero is measured only for named TCP; missing/null counts remain unavailable', async ({ page }) => {
  await fixture(page, false, [
    { ...last, route_id: 'measured-zero', member_id: 'blue', member_active_streams: 0 },
    { ...last, route_id: 'unknown-null', member_id: 'green', member_active_streams: null },
    { ...last, route_id: 'old-server', member_id: 'orange' },
    { ...last, route_id: 'legacy-tcp', member_id: null, member_active_streams: null },
    { ...first, route_id: 'http-member', member_id: 'http-blue', member_active_streams: null },
  ]);
  await page.locator('a[href="#operations"]').click();
  const row = (id) => page.locator('#operations-rows tr').filter({ hasText: id });
  await expect(row('measured-zero')).toContainText('0 established member streams');
  for (const id of ['unknown-null', 'old-server']) {
    await expect(row(id)).toContainText('Member stream count unavailable');
    await expect(row(id)).not.toContainText('0 established member streams');
  }
  await expect(row('legacy-tcp')).toContainText('Route-wide, not per target');
  await expect(row('legacy-tcp')).not.toContainText('established member streams');
  await expect(row('http-member')).toContainText('3 active requests');
  await expect(row('http-member')).not.toContainText('established member streams');
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

test('retired members have independent paging, refresh, escaped values and Korean labels', async ({ page }) => {
  const retiredRows = Array.from({ length: 65 }, (_, index) => ({
    retirement_id: index + 1, protocol: index ? 'tcp' : 'http',
    route_id: index ? `tcp-${index}` : 'api-retired',
    member_id: index ? null : 'blue',
    address: index ? `192.0.2.${index}:443` : '<img src=x onerror="window.__retiredInjected=1">',
    active_admissions: index ? 2 : 3,
  }));
  const calls = await fixture(page, false, [], retiredRows);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  await expect(page.locator('#retired-rows tr')).toHaveCount(64);
  await expect(page.locator('#retired-rows tr').first()).toContainText('3 admission leases');
  await expect(page.locator('#retired-rows tr').first()).toContainText('Member blue');
  await expect(page.locator('#retired-rows')).toContainText(retiredRows[0].address);
  await expect(page.locator('#retired-rows img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__retiredInjected)).toBeUndefined();
  expect(calls.find((call) => call.path === '/v1/retired-members')).toMatchObject({
    search: '?offset=0&limit=64', authorization: `Bearer ${TOKEN}`,
  });
  await page.locator('#retired-next').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(1);
  await expect(page.locator('#retired-range')).toContainText('65–65 of 65');
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#retired-members-title')).toHaveText('교체되어 은퇴한 멤버');
  await expect(page.locator('#retired-rows tr')).toContainText('진행 중인 admission lease 2개');
  await page.locator('#retired-prev').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(64);
  await page.locator('#retired-refresh').click();
  await expect.poll(() => calls.filter((call) => call.path === '/v1/retired-members').length).toBe(4);
  expect(calls.filter((call) => call.path === '/v1/operations')).toHaveLength(1);
});

test('empty retired inventory is instance-local and never presented as completed drain', async ({ page }) => {
  await fixture(page, false, []);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(0);
  await expect(page.locator('#retired-empty')).toBeVisible();
  await expect(page.locator('#retired-range')).toContainText('0–0 of 0');
  await expect(page.locator('#retired-capacity')).toContainText('4,096');
  await expect(page.locator('#view-operations')).toContainText('An empty list does not prove that other instances are drained.');
});

test('a retired second page that drains to zero resets the range and previous control', async ({ page }) => {
  const retiredRows = Array.from({ length: 65 }, (_, index) => ({
    retirement_id: index + 1, protocol: 'tcp', route_id: 'socket', member_id: 'blue',
    address: '192.0.2.10:443', active_admissions: 1,
  }));
  await fixture(page, false, [], retiredRows);
  await page.locator('a[href="#operations"]').click();
  await page.locator('#retired-next').click();
  await expect(page.locator('#retired-range')).toContainText('65–65 of 65');
  retiredRows.splice(0);
  await page.locator('#retired-refresh').click();
  await expect(page.locator('#retired-range')).toContainText('0–0 of 0');
  await expect(page.locator('#retired-prev')).toBeDisabled();
  await expect(page.locator('#retired-rows tr')).toHaveCount(0);
  await expect(page.locator('#retired-empty')).toBeVisible();
});

test('retired refresh failure keeps the last observation and reports the error', async ({ page }) => {
  await fixture(page, false, [], [{ retirement_id: 4, protocol: 'http', route_id: 'api',
    member_id: 'blue', address: 'http://192.0.2.4:80', active_admissions: 1 }]);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(1);
  await page.route('**/v1/retired-members?*', (route) => route.fulfill({ status: 503, json: { title: 'Unavailable' } }));
  await page.locator('#retired-refresh').click();
  await expect(page.locator('#retired-message')).toContainText('Refresh failed; showing last loaded retired members.');
  await expect(page.locator('#retired-rows tr')).toHaveCount(1);
  await expect(page.locator('#retired-empty')).toBeHidden();
  await expect(page.locator('#retired-refresh')).toBeEnabled();
});

test('retired endpoint denial scrubs both privileged tables and delayed responses stay discarded', async ({ page }) => {
  await fixture(page, false, [first], [{ retirement_id: 7, protocol: 'tcp',
    route_id: 'socket', member_id: 'blue', address: '192.0.2.10:443', active_admissions: 2 }]);
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(1);
  await page.route('**/v1/retired-members?*', (route) => route.fulfill({ status: 403, json: { title: 'Forbidden' } }));
  await page.locator('#retired-refresh').click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#retired-rows tr')).toHaveCount(0);
  await expect(page.locator('#operations-rows tr')).toHaveCount(0);
  await page.unroute('**/v1/retired-members?*');

  await page.getByLabel('Administrator token').fill(TOKEN);
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.locator('a[href="#operations"]').click();
  await expect(page.locator('#retired-rows tr')).toHaveCount(1);
  let release;
  let requested;
  const gate = new Promise((resolve) => { release = resolve; });
  const seen = new Promise((resolve) => { requested = resolve; });
  await page.route('**/v1/retired-members?*', async (route) => {
    requested();
    await gate;
    await route.fulfill({ json: { total: 1, offset: 0, limit: 64, capacity: 4096,
      rows: [{ retirement_id: 8, protocol: 'http', route_id: 'late', member_id: null,
        address: 'http://late.example', active_admissions: 1 }] } });
  });
  await page.locator('#retired-refresh').click();
  await seen;
  await expect(page.locator('#retired-message')).toHaveText('Loading retired members…');
  await expect(page.locator('#retired-refresh')).toBeDisabled();
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#retired-rows tr')).toHaveCount(0);
  await expect(page.locator('#retired-rows')).not.toContainText('late');
});

test('viewer cannot navigate to operations or request its administrator API', async ({ page }) => {
  const calls = await fixture(page, true);
  await expect(page.locator('a[href="#operations"]')).toBeHidden();
  await page.evaluate(() => { location.hash = '#operations'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter((call) => call.path === '/v1/operations')).toHaveLength(0);
  expect(calls.filter((call) => call.path === '/v1/retired-members')).toHaveLength(0);
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
