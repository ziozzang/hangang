import { test, expect } from '@playwright/test';

const processId = '0123456789abcdef';
const otherProcess = 'fedcba9876543210';
const digest = 'a'.repeat(64);
const token = 'fixture-tcp-admin';
const geoip = { state: 'known', country: 'KR', generation_sha256: digest, error_code: null };
const activeRecord = (id, overrides = {}) => ({
  connection_id: id, started_at_unix_ms: Date.now() - 1000, elapsed_ms: 1000,
  peer_ip: '2001:db8::1', peer_port: 51000, listen: '0.0.0.0:9001',
  phase: 'forwarding', route_id: 'tcp-api', member_id: 'member-a', geoip,
  bytes_upstream: '9007199254740993', bytes_downstream: '42', ...overrides,
});
const recentRecord = (eventId, overrides = {}) => ({
  ...activeRecord('9007199254740994'), event_id: eventId, ended_at_unix_ms: Date.now(),
  duration_ms: 1200, outcome: 'eof', ...overrides,
});
const activeBatch = (records, overrides = {}) => ({
  process_id: processId, server_time_unix_ms: Date.now(), records,
  latest_connection_id: records.at(-1)?.connection_id ?? '0',
  next_after: records.at(-1)?.connection_id ?? '0',
  active_tracked: records.length, active_untracked: 0, omitted_total: '0',
  capacity: 8192, best_effort: true, ...overrides,
});
const recentBatch = (records, overrides = {}) => ({
  process_id: processId, server_time_unix_ms: Date.now(), records,
  oldest_event_id: records[0]?.event_id ?? '0', latest_event_id: records.at(-1)?.event_id ?? '0',
  next_after: records.at(-1)?.event_id ?? '0', gap: false, dropped_total: '0',
  omitted_total: '0', retention_seconds: 60, capacity: 4096, ...overrides,
});
const event = (name, value) => `event: ${name}\ndata: ${JSON.stringify(value)}\n\n`;

async function fixture(page, { active = activeBatch([]), recent = recentBatch([]), stream, viewer = false,
  activeHandler, recentHandler } = {}) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const request = route.request(); const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, search: url.search, headers: request.headers() });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(viewer
      ? { json: { bootstrap_required: false } } : { status: 404, body: 'missing' });
    if (url.pathname === '/v1/auth/login') return route.fulfill({ json: {
      token: 'fixture-viewer-session', expires_in_seconds: 28800,
      user: { id: 2, username: 'viewer', role: 'viewer', enabled: true },
    } });
    if (url.pathname === '/v1/auth/logout') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/v1/status') return route.fulfill({ json: {
      revision: 1, http_routes: 0, tcp_routes: 1, uptime_seconds: 10,
      version: 'fixture', process_id: 42, instance: { id: processId },
      state: { ready: true, draining: false },
      metrics: { requests_total: 1, errors_total: 0, active_connections: 1 },
    } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/config') return route.fulfill({ json: { revision: 1, http: [], tcp: [] } });
    if (url.pathname === '/v1/traffic') return route.fulfill({ json: {
      records: [], latest_id: 0, next_after: 0, gap: false, dropped_total: 0,
      retention_seconds: 60, server_time_unix_ms: Date.now(),
    } });
    if (url.pathname === '/v1/connections/tcp/active') return activeHandler ? activeHandler(route, url) : route.fulfill({ json: active });
    if (url.pathname === '/v1/connections/tcp/recent') return recentHandler ? recentHandler(route, url) : route.fulfill({ json: recent });
    if (url.pathname === '/v1/events') return stream ? stream(route) : route.fulfill({ status: 503, body: 'stream unavailable' });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  if (viewer) {
    await page.locator('#login-username').fill('viewer');
    await page.locator('#login-password').fill('viewer-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
  } else {
    await page.getByLabel('Administrator token').fill(token);
    await page.getByRole('button', { name: 'Connect' }).click();
  }
  await expect(page.locator('#login-dialog')).toBeHidden();
  return calls;
}

test('active and recent TCP panels preserve 64-bit values, filter and localize distinct states', async ({ page }) => {
  const malicious = '<img src=x onerror="window.__tcpInjected=1">';
  const calls = await fixture(page, {
    active: activeBatch([activeRecord('9007199254740993')], { active_tracked: 2, active_untracked: 3, omitted_total: '5' }),
    recent: recentBatch([recentRecord('9007199254740995', { outcome: 'country_denied', bytes_downstream: '0', listen: malicious })], { gap: true, dropped_total: '2' }),
  });
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(1);
  await expect(page.locator('#tcp-active-rows')).toContainText('9007199254740993');
  await expect(page.locator('#tcp-active-rows')).toContainText('9,007,199,254,740,993');
  await expect(page.locator('#tcp-active-rows')).toContainText('Forwarding');
  await expect(page.locator('#tcp-active-note')).toContainText('3 untracked at sample');
  await expect(page.locator('#tcp-recent-rows')).toContainText('Country denied');
  await expect(page.locator('#tcp-recent-rows')).toContainText(malicious);
  await expect(page.locator('#tcp-recent-rows img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__tcpInjected)).toBeUndefined();
  await expect(page.locator('#tcp-recent-note')).toContainText('cursor gap');
  await expect(page.locator('#tcp-recent-note')).toContainText('unknown intentionally filtered completions');
  await page.locator('#tcp-active-filter').fill('phase:forwarding');
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(1);
  await page.locator('#tcp-active-filter').fill('country:us');
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(0);
  await page.locator('#tcp-recent-filter').fill('outcome:country_denied');
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(1);
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#tcp-recent-rows')).toContainText('국가 정책 거부');
  await expect(page.locator('#tcp-active-note')).toContainText('샘플 시점 미추적 3개');
  expect(calls.filter(call => call.path.startsWith('/v1/connections/tcp/'))).toHaveLength(2);
  expect(calls.find(call => call.path.endsWith('/active')).headers.authorization).toBe(`Bearer ${token}`);
  expect(calls.some(call => call.search.includes(token))).toBe(false);
});

test('TCP completion coverage and revision distinguish filtering, eviction and untracked admission', async ({ page }) => {
  await fixture(page, { active: activeBatch([activeRecord('1')], { omitted_total: '3' }),
    recent: recentBatch([recentRecord('2', { policy_revision: '9007199254740993' })],
      { dropped_total: '4', omitted_total: '3', filtered_total: '5' }) });
  await expect(page.locator('#tcp-active-note')).toContainText('active visibility is unfiltered');
  await expect(page.locator('#tcp-recent-note')).toContainText('4 expired/evicted');
  await expect(page.locator('#tcp-recent-note')).toContainText('3 untracked omissions');
  await expect(page.locator('#tcp-recent-note')).toContainText('5 intentionally filtered completions');
  await expect(page.locator('#tcp-recent-rows')).toContainText('Recording policy revision #9007199254740993');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#tcp-recent-note')).toContainText('의도적으로 생략된 완료 5개');
  await expect(page.locator('#tcp-history-scope')).toContainText('완전하거나 영구적인 감사 이력이 아닙니다');
});

test('missing or malformed TCP completion metadata is unknown, never rounded or displayed as zero', async ({ page }) => {
  await fixture(page, { recent: recentBatch([
    recentRecord('1', { policy_revision: '7\n' }), recentRecord('2', { policy_revision: '18446744073709551616' }),
    recentRecord('3'),
  ], { filtered_total: '5\n' }) });
  await expect(page.locator('#tcp-recent-note')).toContainText('unknown intentionally filtered completions');
  await expect(page.locator('#tcp-recent-rows')).toContainText('Recording policy revision unreported');
  await expect(page.locator('#tcp-recent-rows')).not.toContainText('revision #7');
  await expect(page.locator('#tcp-recent-rows')).not.toContainText('18446744073709551616');
});

test('drop-only empty SSE batch updates TCP filtered count without inventing a completion', async ({ page }) => {
  let release; const gate = new Promise(resolve => { release = resolve; });
  await fixture(page, { recent: recentBatch([], { filtered_total: '0' }),
    stream: async route => { await gate; return route.fulfill({ contentType: 'text/event-stream', body:
      event('status', { revision: 1, http_routes: 0, tcp_routes: 1, uptime_seconds: 11,
        instance: { id: processId }, state: { ready: true }, metrics: { requests_total: 1, active_connections: 0 } }) +
      event('tcp_connections', { active: activeBatch([]), recent: recentBatch([], { filtered_total: '9' }) }) }); } });
  await expect(page.locator('#tcp-recent-note')).toContainText('0 intentionally filtered completions');
  release();
  await expect(page.locator('#tcp-recent-note')).toContainText('9 intentionally filtered completions');
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#tcp-recent-note')).toContainText('cleared');
});

test('delayed recent completion response cannot restore filtered count or rows after logout', async ({ page }) => {
  let release, arrived;
  const gate = new Promise(resolve => { release = resolve; });
  const seen = new Promise(resolve => { arrived = resolve; });
  await fixture(page, { recentHandler: async route => {
    arrived(); await gate;
    return route.fulfill({ json: recentBatch([recentRecord('8', { policy_revision: '7' })], { filtered_total: '12' }) });
  } });
  await seen;
  await page.getByRole('button', { name: 'Log out' }).click();
  release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0);
  await expect(page.locator('#tcp-recent-note')).toContainText('cleared');
  await expect(page.locator('#tcp-recent-note')).not.toContainText('12');
});

test('maximum 64-bit byte values wrap visibly on desktop and narrow screens', async ({ page }) => {
  const max = '18446744073709551615';
  await fixture(page, {
    active: activeBatch([activeRecord('1', { bytes_upstream: max, bytes_downstream: max })]),
    recent: recentBatch([recentRecord('2', { bytes_upstream: max, bytes_downstream: max })]),
  });
  const formatted = '18,446,744,073,709,551,615';
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    for (const selector of ['#tcp-active-rows tr td:last-child', '#tcp-recent-rows tr td:last-child']) {
      const cell = page.locator(selector);
      await expect(cell).toContainText(`upstream ${formatted} B · downstream ${formatted} B`);
      const shape = await cell.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth,
        whiteSpace: getComputedStyle(element).whiteSpace }));
      expect(shape.whiteSpace).toBe('normal');
      expect(shape.scroll, `${selector} clips bytes at ${width}px`).toBeLessThanOrEqual(shape.client + 1);
    }
  }
});

test('SSE updates phases and completions, process replacement clears old rows, logout scrubs metadata', async ({ page }) => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  await fixture(page, {
    active: activeBatch([activeRecord('1', { phase: 'dialing', bytes_upstream: '0' })]),
    stream: async route => { await gate; return route.fulfill({ contentType: 'text/event-stream', body:
      event('status', { revision: 1, http_routes: 0, tcp_routes: 1, uptime_seconds: 11,
        instance: { id: processId }, state: { ready: true }, metrics: { requests_total: 2, errors_total: 0, active_connections: 1 } })
      + event('tcp_connections', { active: activeBatch([activeRecord('1', { phase: 'forwarding', bytes_upstream: '3' })]),
        recent: recentBatch([recentRecord('4', { outcome: 'idle_timeout' })]) }) }); },
  });
  await expect(page.locator('#tcp-active-rows')).toContainText('Dialing');
  release();
  await expect(page.locator('#tcp-active-rows')).toContainText('Forwarding');
  await expect(page.locator('#tcp-recent-rows')).toContainText('Idle timeout');
  await page.evaluate(async id => {
    const { recordStatus } = await import('/ui/console.js');
    recordStatus({ revision: 1, http_routes: 0, tcp_routes: 0, uptime_seconds: 1,
      instance: { id }, state: { ready: true }, metrics: { requests_total: 0, errors_total: 0, active_connections: 0 } });
  }, otherProcess);
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(0);
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#tcp-history-panel')).toBeHidden();
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(0);
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0);
});

test('active pagination is best-effort and delayed responses cannot repaint after logout', async ({ page }) => {
  let releaseDelayed;
  const delayed = new Promise(resolve => { releaseDelayed = resolve; });
  const first = Array.from({ length: 128 }, (_, index) => activeRecord(String(index + 1), { bytes_upstream: '0' }));
  let firstPageCalls = 0;
  await fixture(page, { activeHandler: (route, url) => {
    if (url.searchParams.get('after') === '128') return route.fulfill({ json: activeBatch([activeRecord('129')], { active_tracked: 129 }) });
    firstPageCalls += 1;
    if (firstPageCalls > 1) {
      return delayed.then(() => route.fulfill({ json: activeBatch([activeRecord('999')]) }));
    }
    return route.fulfill({ json: activeBatch(first, { active_tracked: 129, latest_connection_id: '129' }) });
  } });
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(128);
  await expect(page.locator('#tcp-active-note')).toContainText('showing 128 of 129');
  await page.locator('#tcp-active-next').click();
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(1);
  await expect(page.locator('#tcp-active-rows')).toContainText('#129');
  await expect(page.locator('#tcp-active-note')).toContainText('Page 2');
  await page.locator('#tcp-active-first').click(); // Held server response.
  await page.getByRole('button', { name: 'Log out' }).click();
  releaseDelayed();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(0);
  await expect(page.locator('#tcp-active-rows')).not.toContainText('999');
});

test('recent TTL expires while paused and viewer never requests TCP connection metadata', async ({ page }) => {
  await fixture(page, { recent: recentBatch([recentRecord('2')], { retention_seconds: 2 }) });
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(1);
  await page.locator('#tcp-history-pause').click();
  await expect(page.locator('#tcp-history-pause')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0, { timeout: 5000 });
  const viewerPage = await page.context().newPage();
  const calls = await fixture(viewerPage, { viewer: true });
  await expect(viewerPage.locator('#tcp-history-panel')).toBeHidden();
  expect(calls.some(call => call.path.startsWith('/v1/connections/tcp/'))).toBe(false);
  await viewerPage.close();
});

test('TCP history role downgrade clears privileged rows before another response can render', async ({ page }) => {
  let activeCalls = 0;
  await fixture(page, { activeHandler: route => {
    activeCalls += 1;
    return activeCalls === 1 ? route.fulfill({ json: activeBatch([activeRecord('7')]) })
      : route.fulfill({ status: 403, body: 'role revoked' });
  } });
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(1);
  await page.locator('#tcp-history-refresh').click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(0);
  await expect(page.locator('#tcp-recent-rows tr')).toHaveCount(0);
});

test('one bounded post-connect read recovers a completion between initial GET and SSE cursor', async ({ page }) => {
  let recentCalls = 0;
  const calls = await fixture(page, {
    recentHandler: route => {
      recentCalls += 1;
      return route.fulfill({ json: recentCalls === 1 ? recentBatch([])
        : recentBatch([recentRecord('8', { outcome: 'dial_failed' })]) });
    },
    stream: route => route.fulfill({ contentType: 'text/event-stream', body: event('status', {
      revision: 1, http_routes: 0, tcp_routes: 1, uptime_seconds: 11,
      instance: { id: processId }, state: { ready: true },
      metrics: { requests_total: 2, errors_total: 0, active_connections: 0 },
    }) }),
  });
  await expect(page.locator('#tcp-recent-rows')).toContainText('Dial failed');
  expect(calls.filter(call => call.path === '/v1/connections/tcp/recent')).toHaveLength(2);
});

test('an old manual active page cannot replace a newer process observed over SSE', async ({ page }) => {
  let releaseOld, releaseNew;
  const oldPage = new Promise(resolve => { releaseOld = resolve; });
  const newEvent = new Promise(resolve => { releaseNew = resolve; });
  let streamSent = false;
  const first = Array.from({ length: 128 }, (_, index) => activeRecord(String(index + 1), { bytes_upstream: '0' }));
  await fixture(page, {
    activeHandler: (route, url) => url.searchParams.has('after')
      ? oldPage.then(() => route.fulfill({ json: activeBatch([activeRecord('129')]) }).catch(() => {}))
      : route.fulfill({ json: activeBatch(first, { active_tracked: 129, latest_connection_id: '129' }) }),
    stream: async route => {
      if (streamSent) return route.fulfill({ status: 503, body: 'ended' });
      await newEvent; streamSent = true;
      return route.fulfill({ contentType: 'text/event-stream', body: event('tcp_connections', {
        active: activeBatch([activeRecord('1', { route_id: 'new-process' })], { process_id: otherProcess }),
        recent: recentBatch([], { process_id: otherProcess }),
      }) });
    },
  });
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(128);
  await page.locator('#tcp-active-next').click();
  releaseNew();
  await expect(page.locator('#tcp-active-rows')).toContainText('new-process');
  releaseOld();
  await expect(page.locator('#tcp-active-rows tr')).toHaveCount(1);
  await expect(page.locator('#tcp-active-rows')).not.toContainText('#129');
});
