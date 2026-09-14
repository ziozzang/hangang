import { test, expect } from '@playwright/test';

async function fixture(page, initialPolicy = null) {
  const writes = []; let revision = 7;
  let config = { revision, http: [], tcp: [], certificates: [], settings: {
    health_path: '/ready', trusted_proxy_cidrs: ['192.0.2.0/24'],
    http_recording: { default_action: 'drop', rules: [] },
    ...(initialPolicy ? { tcp_recent_recording: structuredClone(initialPolicy) } : {}),
  } };
  await page.route('**/*', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/auth/logout') return route.fulfill({ status: 204 });
    if (path === '/v1/status') return route.fulfill({ json: { revision, http_routes: 0, tcp_routes: 0,
      uptime_seconds: 1, metrics: { requests_total: 1 }, state: { ready: true } } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return route.fulfill({ json: { records: [], latest_id: 0, next_after: 0, gap: false,
      dropped_total: 0, retention_seconds: 60, server_time_unix_ms: Date.now() } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') {
        writes.push({ body: request.postDataJSON(), match: request.headers()['if-match'] });
        config = { ...request.postDataJSON(), revision: ++revision };
      }
      return route.fulfill({ json: config, headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/config/validate') return route.fulfill({ json: { revision } });
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#config-editor')).toHaveValue(/"health_path"/);
  const panel = page.locator('#tcp-recording-section');
  if (!(await panel.evaluate(element => element.open))) await panel.locator('summary').click();
  return { writes, panel };
}

test('native ordered TCP completion policy stages every field and preserves unrelated settings', async ({ page }) => {
  const { writes } = await fixture(page);
  await page.locator('#tcp-recording-enabled').check();
  await page.locator('#tcp-recording-default').selectOption('drop');
  await page.locator('#tcp-recording-add').click();
  await page.locator('#tcp-recording-add').click();
  const cards = page.locator('#tcp-recording-rules .user-card');
  await cards.first().getByLabel('Rule ID').fill('first');
  await cards.nth(1).getByLabel('Rule ID').fill('second');
  await cards.nth(1).getByRole('button', { name: 'Move up' }).click();
  await expect(cards.first().getByLabel('Rule ID')).toHaveValue('second');
  await cards.first().getByLabel('Listen addresses (one IP:port per line)').fill('0.0.0.0:9001\n[fe80::1%1]:9443');
  await cards.first().getByLabel('Peer CIDRs (one per line)').fill('192.0.2.0/24');
  await cards.first().getByLabel('Route IDs (one per line)').fill('tcp-api');
  await cards.first().getByLabel('Route matching').selectOption('true');
  await cards.first().getByLabel('Outcomes (one code per line)').fill('eof\ncountry_denied');
  await cards.nth(1).getByLabel('Action').selectOption('drop');
  const staged = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(staged.settings).toMatchObject({ health_path: '/ready', trusted_proxy_cidrs: ['192.0.2.0/24'],
    http_recording: { default_action: 'drop', rules: [] } });
  expect(staged.settings.tcp_recent_recording).toEqual({ default_action: 'drop', rules: [
    { id: 'second', action: 'record', match: { listen_addresses: ['0.0.0.0:9001', '[fe80::1%1]:9443'],
      peer_cidrs: ['192.0.2.0/24'], route_ids: ['tcp-api'], outcomes: ['eof', 'country_denied'], route_matched: true } },
    { id: 'first', action: 'drop', match: { listen_addresses: [], peer_cidrs: [], route_ids: [], outcomes: [] } },
  ] });
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Revision 8 is active');
  expect(writes).toHaveLength(1);
  expect(writes[0].match).toBe('"7"');
  expect(writes[0].body.settings).toEqual(staged.settings);
});

test('invalid native TCP condition blocks apply, raw JSON round-trips, and removal restores record-all', async ({ page }) => {
  const initial = { default_action: 'drop', rules: [{ id: 'prior', action: 'record', match: {
    listen_addresses: ['127.0.0.1:9000'], outcomes: ['no_route'] } }] };
  const { writes } = await fixture(page, initial);
  const card = page.locator('#tcp-recording-rules .user-card').first();
  await expect(card.getByLabel('Outcomes (one code per line)')).toHaveValue('no_route');
  await card.getByLabel('Listen addresses (one IP:port per line)').fill('example.com:9000');
  await expect(page.locator('#tcp-recording-message')).toContainText('Listen addresses');
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('TCP completion recording:');
  expect(writes).toHaveLength(0);
  await card.getByLabel('Listen addresses (one IP:port per line)').fill('127.0.0.1:9000');
  await expect(page.locator('#tcp-recording-message')).toBeEmpty();
  const staged = JSON.parse(await page.locator('#config-editor').inputValue());
  await page.locator('#config-editor').fill(JSON.stringify({ ...staged, settings: { ...staged.settings,
    tcp_recent_recording: { default_action: 'record', rules: [{ id: 'json', action: 'drop', match: { outcomes: ['io_error'] } }] } } }));
  await expect(card.getByLabel('Rule ID')).toHaveValue('json');
  await page.locator('#tcp-recording-enabled').uncheck();
  const removed = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(removed.settings.tcp_recent_recording).toBeUndefined();
  expect(removed.settings.http_recording).toEqual({ default_action: 'drop', rules: [] });
  await page.locator('#apply-config').click();
  expect(writes).toHaveLength(1);
  expect(writes[0].body.settings.tcp_recent_recording).toBeUndefined();
});

test('Korean policy controls retain an editable draft across locale changes', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  const { panel } = await fixture(page);
  await expect(panel).toContainText('원시 TCP 완료 기록 정책');
  await page.locator('#tcp-recording-enabled').check();
  await page.locator('#tcp-recording-add').click();
  await page.locator('#tcp-recording-rules .user-card input[type="text"]').fill('ko-rule');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#tcp-recording-rules .user-card').getByLabel('Rule ID')).toHaveValue('ko-rule');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#config-editor')).toHaveValue(/"id": "ko-rule"/);
});
