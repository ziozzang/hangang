import { test, expect } from '@playwright/test';

const tls = {
  cert_file: '/etc/hangang/server.pem', key_file: '/etc/hangang/server.key',
  client_ca_file: '/etc/hangang/clients.pem', client_crl_file: null,
  allowed_uri_sans: ['spiffe://example.test/ns/app'], handshake_timeout_ms: 5000,
};
const listener = { id: 'private', listen: '127.0.0.1:9443', tls };
const tcpRoute = { id: 'stream', listen: '127.0.0.1:9001', backends: ['127.0.0.1:5432'], inbound_tls: tls };

async function fixture(page, locale = 'en') {
  let revision = 7;
  let materials = [{ kind: 'http', id: 'private', ready: true }, { kind: 'tcp', id: 'stream', ready: false }];
  const writes = [];
  const document = { revision, http: [], tcp: [tcpRoute], workload_http: [listener, { ...listener, id: 'disabled', listen: '127.0.0.1:9444', enabled: false }], certificates: [] };
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: 0, tcp_routes: 1, uptime_seconds: 1, metrics: {}, state: { ready: true }, workload_materials: materials } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') writes.push(request.postDataJSON());
      return handled.fulfill({ json: document, headers: { etag: '"7"' } });
    }
    if (path === '/v1/routes/tcp') return handled.fulfill({ json: { revision: 7, routes: document.tcp }, headers: { etag: '"7"' } });
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision: 7, routes: [] }, headers: { etag: '"7"' } });
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { setMaterials: (next) => { materials = next; }, setRevision: (next) => { revision = next; }, writes };
}

test('local workload status refreshes without changing the staged document or claiming a stale revision ready', async ({ page }) => {
  await page.clock.install();
  const backend = await fixture(page);
  await page.locator('[data-view="config"]').click();
  await page.locator('#workload-http-panel summary').click();
  const ready = page.locator('#workload-http-list [data-workload-id="private"] .workload-material-state');
  const disabled = page.locator('#workload-http-list [data-workload-id="disabled"] .workload-material-state');
  await expect(ready).toHaveText('Current runtime: ready');
  await expect(disabled).toHaveText('Current runtime: inactive');
  const editor = page.locator('#config-editor');
  const draft = JSON.parse(await editor.inputValue()); draft.settings = { health_path: '/draft-only' };
  await editor.fill(JSON.stringify(draft));
  backend.setMaterials([{ kind: 'http', id: 'private', ready: false }, { kind: 'tcp', id: 'stream', ready: true }]);
  await page.clock.fastForward(5000);
  await expect(ready).toHaveText('Current runtime: blocked');
  await page.locator('#locale-select').selectOption('ko');
  await expect(ready).toHaveText('현재 런타임: 차단됨');
  await page.locator('#locale-select').selectOption('en');
  await expect(ready).toHaveText('Current runtime: blocked');
  expect(JSON.parse(await editor.inputValue()).settings.health_path).toBe('/draft-only');
  expect(backend.writes).toHaveLength(0);
  backend.setRevision(8);
  await page.clock.fastForward(5000);
  await expect(ready).toHaveText('Current runtime: unknown');
  await page.locator('[data-view="tcp"]').click();
  await expect(page.locator('[data-route-id="stream"] .workload-material-state')).toHaveText('Current runtime: unknown');
  await page.locator('#logout-button').click();
  await expect(page.locator('#workload-http-list')).toBeEmpty();
});

test('Korean TCP workload state reports blocked local admission', async ({ page }) => {
  await fixture(page, 'ko');
  await page.locator('[data-view="tcp"]').click();
  await expect(page.locator('[data-route-id="stream"] .workload-material-state')).toHaveText('현재 런타임: 차단됨');
});
