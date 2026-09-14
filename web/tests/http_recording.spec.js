import { test, expect } from '@playwright/test';

const record = (id, path, policy_revision) => ({ id, timestamp_unix_ms: Date.now(), peer_ip: '192.0.2.2', peer_port: 41555,
  client_ip: '198.51.100.8', method: 'GET', path, route_id: 'site', status: 200,
  response_head_ms: 8, protocol: 'h1', tls: false, ...(policy_revision === undefined ? {} : { policy_revision }) });

async function fixture(page, { locale = 'en', initialPolicy, writeStatus = 200, filteredTotal, traffic = [] } = {}) {
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  const writes = []; let revision = 7;
  let config = { revision, http: [], tcp: [], certificates: [], settings: { health_path: '/ready',
    ...(initialPolicy ? { http_recording: structuredClone(initialPolicy) } : {}) } };
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/auth/logout') return handled.fulfill({ status: 204 });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: 0, tcp_routes: 0,
      uptime_seconds: 1, metrics: { requests_total: 1 }, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: traffic, oldest_id: traffic[0]?.id ?? null,
      latest_id: traffic.at(-1)?.id ?? 0, next_after: traffic.at(-1)?.id ?? 0, gap: false,
      dropped_total: 3, retention_seconds: 60, server_time_unix_ms: Date.now(),
      ...(filteredTotal === undefined ? {} : { filtered_total: filteredTotal }) } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') {
        writes.push({ body: request.postDataJSON(), match: request.headers()['if-match'] });
        if (writeStatus !== 200) return handled.fulfill({ status: writeStatus, json: { title: writeStatus === 409 ? 'Revision Conflict' : 'Indeterminate Outcome', detail: 'fixture outcome' } });
        config = { ...request.postDataJSON(), revision: ++revision };
      }
      return handled.fulfill({ json: config, headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/config/validate') return handled.fulfill({ json: { revision } });
    return handled.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { writes };
}
async function openPolicy(page) {
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#config-editor')).toHaveValue(/"health_path"/);
  const panel = page.locator('#http-recording-section');
  if (!(await panel.evaluate((element) => element.open))) await panel.locator('summary').click();
  return panel;
}

test('native ordered HTTP policy mirrors every match field into config CAS and preserves other settings', async ({ page }) => {
  const { writes } = await fixture(page);
  await openPolicy(page);
  await page.locator('#http-recording-enabled').check();
  await page.locator('#http-recording-default').selectOption('drop');
  await page.locator('#http-recording-add').click();
  await page.locator('#http-recording-add').click();
  const cards = page.locator('#http-recording-rules .user-card');
  await cards.first().getByLabel('Rule ID').fill('first');
  await cards.nth(1).getByLabel('Rule ID').fill('second');
  await cards.nth(1).getByRole('button', { name: 'Move up' }).click();
  await expect(cards.first().getByLabel('Rule ID')).toHaveValue('second');
  await cards.first().getByLabel('Methods (one case-sensitive token per line)').fill('GET\ncustom');
  await cards.first().getByLabel('Route IDs (one per line)').fill('site');
  await cards.first().getByLabel('Route matching').selectOption('true');
  await cards.first().getByLabel('Status ranges (one 200-299 per line)').fill('200-299\n503-503');
  await cards.first().getByLabel('Path prefixes (one per line)').fill('/private/');
  await cards.first().getByLabel('Peer CIDRs (one per line)').fill('192.0.2.0/24');
  await cards.first().getByLabel('Client CIDRs (one per line)').fill('2001:db8::/32');
  await cards.first().getByLabel('Action').selectOption('record');
  await cards.nth(1).getByLabel('Action').selectOption('drop');
  await page.locator('#setting-health_path').fill('/next-ready');
  const staged = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(staged.settings.health_path).toBe('/next-ready');
  expect(staged.settings.http_recording).toEqual({ default_action: 'drop', rules: [
    { id: 'second', action: 'record', match: { methods: ['GET', 'custom'], route_ids: ['site'], status_ranges: [{ min: 200, max: 299 }, { min: 503, max: 503 }], path_prefixes: ['/private/'], peer_cidrs: ['192.0.2.0/24'], client_cidrs: ['2001:db8::/32'], route_matched: true } },
    { id: 'first', action: 'drop', match: { methods: [], route_ids: [], status_ranges: [], path_prefixes: [], peer_cidrs: [], client_cidrs: [] } },
  ] });
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Revision 8 is active');
  expect(writes).toHaveLength(1);
  expect(writes[0].match).toBe('"7"');
  expect(writes[0].body.settings.http_recording).toEqual(staged.settings.http_recording);
});

test('bad native draft blocks apply, raw JSON round-trips and policy can be removed', async ({ page }) => {
  const policy = { default_action: 'record', rules: [{ id: 'one', action: 'drop', match: { methods: ['GET'], route_matched: true } }] };
  const { writes } = await fixture(page, { initialPolicy: policy });
  await openPolicy(page);
  const card = page.locator('#http-recording-rules .user-card').first();
  await expect(card.getByLabel('Methods (one case-sensitive token per line)')).toHaveValue('GET');
  await card.getByLabel('Route matching').selectOption('false');
  await card.getByLabel('Route IDs (one per line)').fill('site');
  await expect(page.locator('#http-recording-message')).toContainText('cannot also match specific route IDs');
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('HTTP recording:');
  expect(writes).toHaveLength(0);
  await card.getByLabel('Route IDs (one per line)').fill('');
  await expect(page.locator('#http-recording-message')).toBeEmpty();
  const staged = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(staged.settings.http_recording.rules[0].match.route_matched).toBe(false);
  await page.locator('#config-editor').fill(JSON.stringify({ ...staged, settings: { ...staged.settings,
    http_recording: { default_action: 'record', rules: [{ id: 'json', action: 'drop', match: { path_prefixes: ['/raw'] } }] } } }));
  await expect(card.getByLabel('Rule ID')).toHaveValue('json');
  await page.locator('#http-recording-enabled').uncheck();
  const removed = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(removed.settings).toEqual({ health_path: '/ready' });
  await page.locator('#apply-config').click();
  expect(writes).toHaveLength(1);
  expect(writes[0].body.settings).toEqual({ health_path: '/ready' });
});

for (const writeStatus of [409, 500]) {
  test(`${writeStatus} config outcome does not replay HTTP recording policy`, async ({ page }) => {
    const { writes } = await fixture(page, { writeStatus });
    await openPolicy(page);
    await page.locator('#http-recording-enabled').check();
    await page.locator('#http-recording-default').selectOption('drop');
    await page.locator('#apply-config').click();
    await expect(page.locator('#config-message')).toContainText(writeStatus === 409 ? 'Revision conflict' : 'Indeterminate Outcome');
    expect(writes).toHaveLength(1);
    await expect(page.locator('#config-editor')).toHaveValue(/"http_recording"/);
  });
}

test('live HTTP omission count differs from ring eviction, reports policy revision, and strips old query/Host metadata', async ({ page }) => {
  await fixture(page, { filteredTotal: 12, traffic: [record(1, '/private?session=secret', 7),
    { ...record(2, 'http://secret.example/path?token=private'), raw_host: 'secret.example' }] });
  await expect(page.locator('#activity-note')).toContainText('3 expired / evicted at server');
  await expect(page.locator('#activity-note')).toContainText('12 HTTP response records intentionally omitted');
  await expect(page.locator('#activity-rows')).toContainText('configuration revision #7');
  await expect(page.locator('#activity-rows')).toContainText('revision unreported');
  await expect(page.locator('#activity-rows')).not.toContainText('secret');
  await expect(page.locator('#activity-rows')).not.toContainText('token=private');
  await expect(page.locator('#activity-rows')).not.toContainText('secret.example');
});

test('older batch has unknown coverage; Korean settings and counter copy are localized', async ({ page }) => {
  await fixture(page, { locale: 'ko', traffic: [record(1, '/ok')] });
  await expect(page.locator('#activity-note')).toContainText('기록 필터 적용 범위를 알 수 없습니다');
  await openPolicy(page);
  await expect(page.locator('#http-recording-section')).toContainText('HTTP 요청 기록 정책');
  await page.locator('#http-recording-enabled').check();
  await page.locator('#http-recording-default').selectOption('drop');
  await page.locator('#http-recording-add').click();
  await page.locator('#http-recording-rules .user-card').locator('input[type="text"]').first().fill('ko-draft');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#http-recording-rules .user-card').getByLabel('Rule ID')).toHaveValue('ko-draft');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#config-editor')).toHaveValue(/"default_action": "drop"/);
});


test('server-valid repeated alternatives remain editable and unsafe counters are not rounded', async ({ page }) => {
  const initialPolicy = { rules: [{ id: 'repeat', action: 'drop', match: { methods: ['GET', 'GET'] } }] };
  const { writes } = await fixture(page, { initialPolicy, filteredTotal: Number.MAX_SAFE_INTEGER + 1 });
  await expect(page.locator('#activity-note')).toContainText('Recording-filter coverage is unknown');
  await openPolicy(page);
  await expect(page.locator('#http-recording-message')).toBeEmpty();
  const card = page.locator('#http-recording-rules .user-card').first();
  await expect(card.getByLabel('Methods (one case-sensitive token per line)')).toHaveValue('GET\nGET');
  await card.getByLabel('Rule ID').fill('renamed');
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Revision 8 is active');
  expect(writes[0].body.settings.http_recording.rules[0].match.methods).toEqual(['GET', 'GET']);
});
