import { test, expect } from '@playwright/test';

const baseRoute = {
  id: 'stream', listen: '127.0.0.1:9001', backends: ['127.0.0.1:5432'],
  priority: 0, sni: null, deny_cidrs: [],
};
const inboundTls = {
  cert_file: '/etc/hangang/server.crt', key_file: '/etc/hangang/server.key',
  client_ca_file: '/etc/hangang/client-ca.crt', client_crl_file: '/etc/hangang/client.crl',
  allowed_uri_sans: ['spiffe://example.test/ns/default/sa/service'], handshake_timeout_ms: 4500,
};

async function fixture(page, initial = baseRoute, locale = 'en') {
  const route = structuredClone(initial);
  const writes = [];
  let revision = 3;
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: 0, tcp_routes: 1, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') return handled.fulfill({ json: { revision, http: [], tcp: [route], certificates: [] }, headers: { etag: `"${revision}"` } });
    if (path === '/v1/routes/tcp') return handled.fulfill({ json: { revision, routes: [route] }, headers: { etag: `"${revision}"` } });
    if (path === '/v1/routes/tcp/stream') {
      if (request.method() === 'PUT') {
        const written = request.postDataJSON(); writes.push(written); Object.assign(route, written); revision++;
        return handled.fulfill({ json: { revision }, headers: { etag: `"${revision}"` } });
      }
      return handled.fulfill({ json: route, headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision, routes: [] }, headers: { etag: `"${revision}"` } });
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="tcp"]').click();
  return writes;
}

async function edit(page, locale = 'en') {
  await page.locator('[data-route-id="stream"]').getByRole('button', { name: locale === 'ko' ? '편집' : 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
  const section = page.locator('#route-field-inbound_tls_enabled').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

test('native inbound mTLS fields save file paths and exact SPIFFE identities', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-field-inbound_tls_enabled').check();
  for (const [name, value] of Object.entries(inboundTls)) {
    if (name === 'allowed_uri_sans') await page.locator('#route-field-inbound_tls_allowed_uri_sans').fill(value.join('\n'));
    else await page.locator(`#route-field-inbound_tls_${name}`).fill(String(value));
  }
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].inbound_tls).toEqual(inboundTls);
  expect(writes[0].sni).toBeNull();
});

test('advanced JSON mTLS add and removal survive unrelated native edits', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const added = JSON.parse(await json.inputValue());
  added.inbound_tls = structuredClone(inboundTls);
  await json.fill(JSON.stringify(added));
  await expect(page.locator('#route-field-inbound_tls_enabled')).toBeChecked();
  await expect(page.locator('#route-field-inbound_tls_cert_file')).toHaveValue(inboundTls.cert_file);
  await page.locator('#route-field-priority').fill('4');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].inbound_tls).toEqual(added.inbound_tls);

  await edit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const removed = JSON.parse(await json.inputValue()); removed.inbound_tls = null;
  await json.fill(JSON.stringify(removed));
  await expect(page.locator('#route-field-inbound_tls_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('5');
  await page.locator('#save-route').click();
  expect(writes[1].inbound_tls).toBeNull();
});

test('SNI passthrough and inbound mTLS cannot be saved together', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-field-inbound_tls_enabled').check();
  await page.locator('#route-field-inbound_tls_cert_file').fill(inboundTls.cert_file);
  await page.locator('#route-field-inbound_tls_key_file').fill(inboundTls.key_file);
  await page.locator('#route-field-inbound_tls_client_ca_file').fill(inboundTls.client_ca_file);
  await page.locator('#route-field-inbound_tls_allowed_uri_sans').fill(inboundTls.allowed_uri_sans[0]);
  const sniSection = page.locator('#route-field-sni_hosts').locator('xpath=ancestor::details[1]');
  await sniSection.locator('summary').click();
  await page.locator('#route-field-sni_hosts').fill('db.example.test');
  await expect(page.locator('#route-message')).toContainText('cannot be combined with SNI passthrough');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('malformed advanced inbound TLS cannot be silently normalized', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue()); draft.inbound_tls = { cert_file: inboundTls.cert_file };
  await json.fill(JSON.stringify(draft));
  await page.locator('#route-field-priority').fill('6');
  await expect(page.locator('#route-message')).toContainText('allowed_uri_sans array');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('noncanonical SPIFFE identities and material paths are rejected before save', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-field-inbound_tls_enabled').check();
  await page.locator('#route-field-inbound_tls_cert_file').fill(inboundTls.cert_file);
  await page.locator('#route-field-inbound_tls_key_file').fill(inboundTls.key_file);
  await page.locator('#route-field-inbound_tls_client_ca_file').fill(inboundTls.client_ca_file);
  const identity = page.locator('#route-field-inbound_tls_allowed_uri_sans');
  for (const invalid of [
    'spiffe://Example.test/ns/service', 'spiffe://example.test:443/ns/service',
    'spiffe://user@example.test/ns/service', 'spiffe://example.test/ns/%2e/service',
    'spiffe://example.test/ns/../service', 'spiffe://example.test/ns/service/',
  ]) {
    await identity.fill(invalid);
    await expect(page.locator('#route-message')).toContainText('distinct exact SPIFFE URIs');
  }
  await identity.fill(inboundTls.allowed_uri_sans[0]);
  const certificate = page.locator('#route-field-inbound_tls_cert_file');
  for (const invalid of ['/etc/./hangang/server.crt', '/etc//hangang/server.crt', '/etc/../hangang/server.crt']) {
    await certificate.fill(invalid);
    await expect(page.locator('#route-message')).toContainText('absolute normalized file path');
  }
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('Korean inbound mTLS copy and existing TCP passthrough stay intact', async ({ page }) => {
  const writes = await fixture(page, baseRoute, 'ko');
  await edit(page, 'ko');
  await expect(page.locator('label[for="route-field-inbound_tls_enabled"]')).toContainText('수신 클라이언트 인증서 요구');
  await expect(page.locator('#route-field-inbound_tls_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('1');
  await page.locator('#save-route').click();
  expect(writes[0]).not.toHaveProperty('inbound_tls');
});
