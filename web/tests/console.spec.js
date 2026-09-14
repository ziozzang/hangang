import { test, expect } from '@playwright/test';

const TOKEN = 'fixture-admin-token';
const baseStatus = {
  revision: 3, http_routes: 2, tcp_routes: 1, uptime_seconds: 10,
  version: 'test', process_id: 42, state: { ready: true, draining: false },
  metrics: { requests_total: 0, errors_total: 0, active_connections: 1 },
};
const statusAt = (uptime, requests, errors = 0) => ({
  ...baseStatus, uptime_seconds: uptime,
  metrics: { ...baseStatus.metrics, requests_total: requests, errors_total: errors },
});
const event = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
const traffic = (records, retentionSeconds = 60, droppedTotal = 0, serverTime = Date.now()) => ({
  records, oldest_id: records[0]?.id ?? null, latest_id: records.at(-1)?.id ?? 0,
  next_after: records.at(-1)?.id ?? 0, gap: false,
  dropped_total: droppedTotal, retention_seconds: retentionSeconds,
  server_time_unix_ms: serverTime,
});
const record = (id, overrides = {}) => ({
  id, timestamp_unix_ms: Date.now(), peer_ip: '192.0.2.4', peer_port: 44000,
  client_ip: '198.51.100.9', method: 'GET', path: '/health', route_id: 'api',
  status: 200, response_head_ms: 12, protocol: 'HTTP/1.1', tls: true,
  ...overrides,
});

async function fixtures(page, { account = false, viewer = false, stream, snapshot = traffic([]), config, status = baseStatus } = {}) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, url: request.url(), method: request.method(), headers: request.headers() });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(account
      ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') return route.fulfill({ json: {
      token: viewer ? 'fixture-viewer-session' : TOKEN, expires_in_seconds: 28800,
      user: { id: viewer ? 'viewer' : 'owner', username: viewer ? 'viewer' : 'owner',
        role: viewer ? 'viewer' : 'admin', enabled: true },
    } });
    if (url.pathname === '/v1/auth/logout') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/v1/status') return route.fulfill({ json: status });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/traffic') return route.fulfill({ json: typeof snapshot === 'function' ? await snapshot() : snapshot });
    if (url.pathname === '/v1/events') {
      if (stream) return stream(route, calls);
      return route.fulfill({ status: 503, body: 'stream unavailable' });
    }
    if (url.pathname === '/v1/config') return route.fulfill({ json: config || {
      revision: 3, http: [], tcp: [], settings: { trusted_proxy_cidrs: [] },
    } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  return calls;
}

async function signIn(page, viewer = false) {
  await page.goto('/ui/');
  if (viewer) {
    await page.locator('#login-username').fill('viewer');
    await page.locator('#login-password').fill('viewer-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
  } else {
    await page.getByLabel('Administrator token').fill(TOKEN);
    await page.getByRole('button', { name: 'Connect' }).click();
  }
  await expect(page.locator('#login-dialog')).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
}

test('Lua capacity card distinguishes missing metrics from zero and follows status SSE and locale', async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const initial = { ...baseStatus, metrics: { ...baseStatus.metrics, policy_errors_total: 2 } };
  const updated = { ...initial, uptime_seconds: 11, metrics: { ...initial.metrics,
    policy_errors_total: 5, policy_capacity_rejections_total: 3 } };
  const calls = await fixtures(page, { status: initial, stream: async (route) => {
    await gate;
    await route.fulfill({ contentType: 'text/event-stream', body: event('status', updated) });
  } });
  await signIn(page);
  const capacity = page.locator('#secondary-metric-grid .metric').filter({ has: page.locator('.metric-label', { hasText: 'Lua capacity rejections' }) });
  const policy = page.locator('#secondary-metric-grid .metric').filter({ has: page.locator('.metric-label', { hasText: 'Policy errors' }) });
  await expect(capacity.locator('.metric-value')).toHaveText('—');
  await expect(policy.locator('.metric-value')).toHaveText('2');
  await expect(policy.locator('.metric-note')).toHaveText('Lua policy failures, including capacity rejections');
  release();
  await expect(capacity.locator('.metric-value')).toHaveText('3');
  await expect(policy.locator('.metric-value')).toHaveText('5');
  await expect(capacity.locator('.metric-note')).toHaveText('Worker busy or restarting; counted in policy errors');
  await page.locator('#locale-select').selectOption('ko');
  const koreanCapacity = page.locator('#secondary-metric-grid .metric').filter({ has: page.locator('.metric-label', { hasText: 'Lua 용량 거부' }) });
  await expect(koreanCapacity.locator('.metric-value')).toHaveText('3');
  await expect(koreanCapacity.locator('.metric-note')).toHaveText('작업자가 바쁘거나 재시작 중 · 정책 오류에 포함');
  await expect(page.locator('#secondary-metric-grid .metric').filter({ has: page.locator('.metric-label', { hasText: '정책 오류' }) }).locator('.metric-value')).toHaveText('5');
  expect(calls.filter((call) => call.path === '/v1/events').length).toBe(1);
});

test('Lua capacity card renders an explicit zero reported by the server', async ({ page }) => {
  await fixtures(page, { status: { ...baseStatus, metrics: {
    ...baseStatus.metrics, policy_errors_total: 0, policy_capacity_rejections_total: 0,
  } } });
  await signIn(page);
  const capacity = page.locator('#secondary-metric-grid .metric').filter({ has: page.locator('.metric-label', { hasText: 'Lua capacity rejections' }) });
  await expect(capacity.locator('.metric-value')).toHaveText('0');
});

test('chart begins empty and plots only observed counter deltas from the authenticated SSE stream', async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const calls = await fixtures(page, { stream: async (route) => {
    await gate;
    await route.fulfill({ contentType: 'text/event-stream', body:
      event('status', statusAt(11, 8, 1)) + event('status', statusAt(12, 18, 2)) });
  } });
  await signIn(page);
  await expect(page.locator('#chart-empty')).toBeVisible();
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', '');
  await expect(page.locator('#traffic-rate')).toHaveText('—');
  release();
  await expect(page.locator('#traffic-line')).not.toHaveAttribute('d', '');
  await expect(page.locator('#traffic-chart')).toHaveAttribute('aria-label', /observed samples/);
  await expect(page.locator('#traffic-rate')).not.toHaveText('—');
  const stream = calls.find((call) => call.path === '/v1/events');
  expect(stream.headers.authorization).toBe(`Bearer ${TOKEN}`);
  expect(stream.headers.accept).toBe('text/event-stream');
  expect(new URL(stream.url).search).toBe('');
  expect(stream.url).not.toContain(TOKEN);
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage), cookie: document.cookie })))
    .toEqual({ local: [], session: [], cookie: '' });
});

test('request metadata is escaped, filterable, pausable, and expires even while paused', async ({ page }) => {
  const serverTime = 1_750_000_000_000;
  await page.clock.install({ time: new Date(serverTime - 1000) });
  await page.clock.pauseAt(serverTime);
  let release;
  let streamDelivered = false;
  const gate = new Promise((resolve) => { release = resolve; });
  const evil = '<img src=x onerror="window.__injected=1">';
  const first = record(1, { timestamp_unix_ms: serverTime, client_ip: evil, peer_ip: evil, path: `/path/${evil}`, route_id: evil });
  const second = record(2, { timestamp_unix_ms: serverTime, client_ip: '203.0.113.9', path: '/new-path', route_id: 'new-route' });
  await fixtures(page, { snapshot: traffic([first], 2, 0, serverTime), stream: async (route) => {
    if (streamDelivered) return route.fulfill({ status: 503, body: 'stream ended' });
    await gate;
    streamDelivered = true;
    await route.fulfill({ contentType: 'text/event-stream', body:
      event('status', statusAt(11, 2)) + event('traffic', traffic([second], 2, 1, serverTime)) });
  } });
  await signIn(page);
  const frozenTime = await page.evaluate(() => performance.now());
  await new Promise((resolve) => setTimeout(resolve, 30));
  expect(await page.evaluate(() => performance.now())).toBe(frozenTime);
  const rows = page.locator('#activity-rows tr');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(evil);
  await expect(page.locator('#activity-rows img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__injected)).toBeUndefined();
  await page.locator('#activity-search').fill('unmatched');
  await expect(rows).toHaveCount(0);
  await expect(page.locator('#activity-empty')).toContainText('No recent requests match');
  await page.locator('#activity-search').fill('');
  await expect(rows).toHaveCount(1);
  await page.locator('#activity-pause').click();
  await expect(page.locator('#activity-pause')).toHaveAttribute('aria-pressed', 'true');
  release();
  await expect(page.locator('#activity-note')).toContainText('1 expired / evicted');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).not.toContainText('/new-path');
  await page.locator('#activity-pause').click();
  await expect(rows).toHaveCount(2);
  await page.locator('#activity-search').fill('203.0.113.9');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('/new-path');
  await page.locator('#activity-search').fill('');
  await page.locator('#activity-pause').click();
  await page.clock.runFor(3000);
  expect((await page.evaluate(() => performance.now())) - frozenTime).toBeGreaterThanOrEqual(3000);
  await expect(rows).toHaveCount(0, { timeout: 5000 });
});

test('server timestamp bounds the remaining TTL when the browser wall clock is behind', async ({ page }) => {
  await page.addInitScript(() => {
    const actualNow = Date.now.bind(Date);
    Date.now = () => actualNow() - 10 * 60 * 1000;
  });
  await fixtures(page, { snapshot: () => {
    const serverNow = Date.now();
    return traffic([record(1, { timestamp_unix_ms: serverNow - 1000 })], 2, 0, serverNow);
  } });
  await signIn(page);
  const rows = page.locator('#activity-rows tr');
  await expect(rows).toHaveCount(1);
  await page.locator('#activity-pause').click();
  await expect(rows).toHaveCount(0, { timeout: 4000 });
});

test('locale changes translate paused rows without admitting new or expired traffic', async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const first = record(1, { route_id: null, path: '/first' });
  const second = record(2, { route_id: 'new-route', path: '/second' });
  await fixtures(page, { snapshot: traffic([first], 3), stream: async (route) => {
    await gate;
    await route.fulfill({ contentType: 'text/event-stream', body:
      event('status', statusAt(11, 2)) + event('traffic', traffic([second], 3, 1)) });
  } });
  await signIn(page);
  const rows = page.locator('#activity-rows tr');
  await expect(rows).toHaveCount(1);
  await expect(rows.first().locator('td').nth(3)).toHaveText('UnmatchedRecording policy revision unreportedListener unknown');
  await page.locator('#activity-pause').click();
  release();
  await expect(page.locator('#activity-note')).toContainText('1 expired / evicted');
  await page.locator('#locale-select').selectOption('ko');
  await expect(rows).toHaveCount(1);
  await expect(rows.first().locator('td').nth(1).locator('small')).toContainText('피어');
  await expect(rows.first().locator('td').nth(3)).toContainText('일치하는 라우트 없음');
  await expect(rows.first()).not.toContainText('/second');
  await expect(rows).toHaveCount(0, { timeout: 5000 });
  await expect(page.locator('#activity-count')).toHaveText('최근 요청: 0건');
  await page.locator('#locale-select').selectOption('en');
  await expect(rows).toHaveCount(0);
  await expect(page.locator('#activity-count')).toHaveText('Recent requests: 0');
});

test('counter and instance resets discard chart history until a new delta is observed', async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await fixtures(page, { stream: async (route) => {
    await gate;
    await route.fulfill({ status: 503, body: 'stream unavailable' });
  } });
  await signIn(page);
  const emit = (status) => page.evaluate(async (data) => {
    const { recordStatus } = await import('/ui/console.js');
    recordStatus(data);
  }, status);
  await emit(statusAt(11, 10));
  await expect(page.locator('#traffic-line')).not.toHaveAttribute('d', '');
  await emit(statusAt(12, 2));
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', '');
  await expect(page.locator('#chart-empty')).toBeVisible();
  await emit(statusAt(13, 9));
  await expect(page.locator('#traffic-line')).not.toHaveAttribute('d', '');
  await emit({ ...statusAt(14, 1), instance: { id: 'replacement-instance' } });
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', '');
  await emit({ ...statusAt(15, 6), instance: { id: 'replacement-instance' } });
  await expect(page.locator('#traffic-line')).not.toHaveAttribute('d', '');
  release();
});

test('auth_expired stream event clears authenticated data and prevents reconnect', async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const calls = await fixtures(page, { snapshot: traffic([record(1)]), stream: async (route) => {
    await gate;
    await route.fulfill({ contentType: 'text/event-stream', body: 'event: auth_expired\n\n' });
  } });
  await signIn(page);
  await expect(page.locator('#activity-rows tr')).toHaveCount(1);
  release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#activity-rows tr')).toHaveCount(0);
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', '');
  await expect(page.locator('#stream-state')).toHaveText('Stream paused');
  await page.waitForTimeout(2200);
  expect(calls.filter((call) => call.path === '/v1/events')).toHaveLength(1);
});

test('logout scrubs stream data and viewer never requests or renders administrator telemetry', async ({ page }) => {
  const calls = await fixtures(page, { snapshot: traffic([record(1)]), stream: (route) =>
    route.fulfill({ contentType: 'text/event-stream', body: event('status', statusAt(11, 3)) }) });
  await signIn(page);
  await expect(page.locator('#activity-rows tr')).toHaveCount(1);
  await page.getByRole('link', { name: 'Security' }).click();
  await expect(page.locator('#security-content .metric')).toHaveCount(4);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#activity-rows tr')).toHaveCount(0);
  await expect(page.locator('#security-content')).toBeEmpty();
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', '');
  await expect(page.locator('#stream-state')).toHaveText('Stream paused');
  expect(calls.some((call) => call.path === '/v1/traffic')).toBe(true);

  const viewerPage = await page.context().newPage();
  const viewerCalls = await fixtures(viewerPage, { account: true, viewer: true,
    stream: (route) => route.fulfill({ contentType: 'text/event-stream', body:
      event('status', statusAt(11, 4)) + event('traffic', traffic([record(7)])) }) });
  await signIn(viewerPage, true);
  await expect(viewerPage.locator('#activity-panel')).toBeHidden();
  await expect(viewerPage.getByRole('link', { name: 'Security' })).toBeHidden();
  await expect(viewerPage.locator('#activity-rows tr')).toHaveCount(0);
  expect(viewerCalls.filter((call) => call.path === '/v1/traffic' || call.path === '/v1/config')).toHaveLength(0);
  await viewerPage.close();
});

test('theme persists only by user choice, command search navigates, and narrow dashboard stays within viewport', async ({ page }) => {
  await fixtures(page);
  await signIn(page);
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  const initialTheme = await page.locator('html').getAttribute('data-theme');
  await page.locator('#theme-toggle').click();
  const chosenTheme = await page.locator('html').getAttribute('data-theme');
  expect(chosenTheme).not.toBe(initialTheme);
  expect(await page.evaluate(() => Object.entries(localStorage))).toEqual([['hangang-theme', chosenTheme]]);
  await page.keyboard.press('Control+k');
  await expect(page.locator('#command-dialog')).toBeVisible();
  await page.locator('#command-search').fill('security');
  await expect(page.locator('.command-result')).toHaveCount(1);
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#security$/);
  await expect(page.locator('#command-dialog')).toBeHidden();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', chosenTheme);
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  const dimensions = await page.evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width + 1);
});

test('request history attributes the same route on default, public and workload listeners', async ({ page }) => {
  const rows = [
    record(1, { route_id: 'shared', listener: { kind: 'default', id: 'default' } }),
    record(2, { route_id: 'shared', listener: { kind: 'public', id: 'edge' } }),
    record(3, { route_id: 'shared', listener: { kind: 'workload', id: 'private-edge' } }),
    record(4, { route_id: 'shared' }),
    record(5, { route_id: 'shared', listener: { kind: 'invented', id: '<img src=x onerror=alert(1)>' } }),
  ];
  await fixtures(page, { snapshot: traffic(rows) });
  await signIn(page);
  const activity = page.locator('#activity-rows tr');
  await expect(activity).toHaveCount(5);
  await expect(activity.filter({ has: page.locator('.traffic-listener', { hasText: 'Default CLI listener' }) })).toHaveCount(1);
  await expect(activity.filter({ has: page.locator('.traffic-listener', { hasText: 'Public listener: edge' }) })).toHaveCount(1);
  await expect(activity.filter({ has: page.locator('.traffic-listener', { hasText: 'Workload mTLS listener: private-edge' }) })).toHaveCount(1);
  await expect(activity.filter({ has: page.locator('.traffic-listener', { hasText: 'Listener unknown' }) })).toHaveCount(2);
  await expect(page.locator('#activity-rows img')).toHaveCount(0);
  await expect(page.locator('#activity-rows')).not.toContainText('<img');
  await expect(activity.filter({ has: page.locator('.traffic-listener', { hasText: 'Public listener: edge' }) }).locator('td').nth(2)).toHaveAttribute('title', /Public listener: edge/);
  await page.locator('#activity-search').fill('listener:edge');
  await expect(activity).toHaveCount(1);
  await page.locator('#activity-search').fill('default');
  await expect(activity).toHaveCount(1);
  await page.locator('#activity-search').fill('unknown');
  await expect(activity).toHaveCount(2);
});

test('paused Korean request history translates listener provenance while keeping exact IDs', async ({ page }) => {
  await fixtures(page, { snapshot: traffic([
    record(1, { listener: { kind: 'public', id: 'edge' } }),
    record(2, { listener: { kind: 'workload', id: 'orders' } }),
    record(3),
  ]) });
  await signIn(page);
  await page.locator('#activity-pause').click();
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#activity-rows .traffic-listener')).toContainText(['리스너 알 수 없음', '워크로드 mTLS 리스너: orders', '공개 리스너: edge']);
  await expect(page.locator('#activity-search')).toHaveAttribute('placeholder', 'IP, 메서드, 경로, 라우트, 리스너 필터…');
  await page.locator('#activity-pause').click();
  await page.locator('#activity-search').fill('orders');
  await expect(page.locator('#activity-rows tr')).toHaveCount(1);
});

test('late traffic snapshot after logout cannot restore listener provenance', async ({ page }) => {
  let release, waiting = false;
  await fixtures(page, { snapshot: async () => { waiting = true; await new Promise(resolve => { release = resolve; });
    return traffic([record(1, { listener: { kind: 'public', id: 'edge' } })]); } });
  await signIn(page);
  await expect.poll(() => waiting).toBe(true);
  await page.locator('#logout-button').click();
  const staleResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/traffic');
  release();
  await staleResponse;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(page.locator('#activity-rows')).toBeEmpty();
  await expect(page.locator('#activity-panel')).toBeHidden();
});

test('request history rejects malformed known listener kinds without losing valid workload IDs', async ({ page }) => {
  const longPublicId = 'a'.repeat(65);
  const longWorkloadId = 'b'.repeat(129);
  const cases = [
    [11, { kind: 'public', id: 'default' }, 'Listener unknown'],
    [12, { kind: 'public', id: 'edge:port' }, 'Listener unknown'],
    [13, { kind: 'public', id: longPublicId }, 'Listener unknown'],
    [19, { kind: 'public', id: 'edge\n' }, 'Listener unknown'],
    [14, { kind: 'default', id: 'edge' }, 'Listener unknown'],
    [15, { kind: 'default', id: null }, 'Listener unknown'],
    [16, { kind: 'workload', id: 'private:edge' }, 'Workload mTLS listener: private:edge'],
    [17, { kind: 'workload', id: longWorkloadId }, 'Listener unknown'],
    [18, { kind: 'workload', id: 'private edge' }, 'Listener unknown'],
    [20, { kind: 'workload', id: 'private:edge\n' }, 'Listener unknown'],
  ];
  await fixtures(page, { snapshot: traffic(cases.map(([id, listener]) => record(id, { route_id: 'shared', listener }))) });
  await signIn(page);
  for (const [id, , label] of cases) await expect(page.locator(`#activity-rows tr[data-id="${id}"] .traffic-listener`)).toHaveText(label);
  await expect(page.locator('#activity-rows')).not.toContainText(longPublicId);
  await expect(page.locator('#activity-rows')).not.toContainText(longWorkloadId);
  await page.locator('#activity-search').fill('private:edge');
  await expect(page.locator('#activity-rows tr')).toHaveCount(1);
  await expect(page.locator('#activity-rows tr')).toHaveAttribute('data-id', '16');
});

test('live traffic event carries listener provenance into request detail', async ({ page }) => {
  await fixtures(page, { snapshot: traffic([]), stream: route => route.fulfill({ contentType: 'text/event-stream', body:
    event('status', statusAt(11, 1)) + event('traffic', traffic([record(7, { route_id: 'shared', listener: { kind: 'public', id: 'edge' } })])) }) });
  await signIn(page);
  const row = page.locator('#activity-rows tr[data-id="7"]');
  await expect(row.locator('.traffic-listener')).toHaveText('Public listener: edge');
  await expect(row.locator('td').nth(2)).toHaveAttribute('title', /Public listener: edge/);
});
