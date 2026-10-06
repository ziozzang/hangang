import { test, expect } from '@playwright/test';

async function fixture(page, challenge = null, showAdvanced = true) {
  const writes = [];
  let route = { id: 'site', hosts: ['example.test', 'www.example.test'], listener_ids: ['default', 'edge'], path_prefix: '/', backends: ['http://origin:8080'], headers: {}, json: {}, priority: 9, future_policy: { preserved: true }, ...(challenge ? { acme_http01: challenge } : {}) };
  await page.route('**/*', async handled => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: '' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision: 7, http_routes: 1, tcp_routes: 0, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: '' });
    if (path === '/v1/config') return handled.fulfill({ json: { revision: 7, http: [route], tcp: [], public_http: [{ id: 'edge', listen: '127.0.0.1:8081' }] }, headers: { etag: '"7"' } });
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision: 7, routes: [route] }, headers: { etag: '"7"' } });
    if (path === '/v1/routes/http/site') {
      if (request.method() === 'PUT') { route = request.postDataJSON(); writes.push(route); return handled.fulfill({ json: { revision: 8 }, headers: { etag: '"8"' } }); }
      return handled.fulfill({ json: route, headers: { etag: '"7"' } });
    }
    return handled.fulfill({ status: 404, body: '' });
  });
  await page.goto('/ui/'); await page.locator('#token-input').fill('fixture-token'); await page.locator('#login-submit').click(); await expect(page.locator('#login-dialog')).toBeHidden();
  const edit = async () => {
    await page.locator('[data-view="http"]').click(); await page.locator('[data-route-id="site"] td:last-child button').first().click();
    const section = page.locator('[name="acme_http01_enabled"]').locator('xpath=ancestor::details[1]');
    if (!(await section.evaluate(el => el.open))) await section.locator(':scope > summary').click();
    if (showAdvanced) { await expect(async () => { const advanced = page.locator('[name="acme_http01_backend"]').locator('xpath=ancestor::details[1]'); if (!(await advanced.evaluate(el => el.open))) await advanced.locator(':scope > summary').click(); await expect(page.locator('[name="acme_http01_backend"]')).toBeVisible({ timeout: 500 }); }).toPass(); }
  };
  await edit(); return { writes, edit };
}

test('domain route HTTP-01 forwarding edits, preserves JSON and removes without separate rows', async ({ page }) => {
  const { writes, edit } = await fixture(page);
  await expect(page.locator('[name="acme_http01_enabled"]')).toBeChecked();
  await page.getByLabel('ACME allow').check();
  await page.getByLabel('HTTP-01 issuer backend').fill('docker://acme-issuer/edge/8080');
  await page.getByLabel('HTTP-01 listener IDs').fill('edge');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0]).toMatchObject({ acme_http01: { backend: 'docker://acme-issuer/edge/8080', listener_ids: ['edge'] }, priority: 9, future_policy: { preserved: true }, backends: ['http://origin:8080'] });
  await expect(page.locator('.route-table tbody tr')).toHaveCount(1);
  await edit();
  await expect(page.getByLabel('HTTP-01 issuer backend')).toHaveValue('docker://acme-issuer/edge/8080');
  await page.getByLabel('HTTP-01 listener IDs').fill('');
  await page.getByLabel('HTTP-01 issuer backend').fill('http://issuer:8080');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[1].acme_http01).toEqual({ backend: 'http://issuer:8080' });
  await edit(); await page.locator('[name="acme_http01_enabled"]').uncheck();
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[2].acme_http01).toEqual({ backend: 'http://issuer:8080', allow: false }); expect(writes[2].future_policy).toEqual({ preserved: true });
  await edit(); await page.locator('[name="acme_http01_enabled"]').check();
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[3].acme_http01).toEqual({ backend: 'http://issuer:8080' });
  await edit(); await page.locator('[name="acme_http01_backend"]').fill('');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[4]).not.toHaveProperty('acme_http01');
});

test('advanced HTTP-01 JSON survives unrelated native edits and invalid issuer scope cannot publish', async ({ page }) => {
  const { writes } = await fixture(page);
  const draft = JSON.parse(await page.locator('#route-json').inputValue()); draft.acme_http01 = { backend: 'http://issuer:8080', listener_ids: ['edge'] };
  const advanced = page.locator('#route-json').locator('xpath=ancestor::details[1]');
  if (!(await advanced.evaluate(el => el.open))) await advanced.locator(':scope > summary').click();
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await page.getByLabel('Retries', { exact: true }).fill('2');
  await expect(page.locator('#route-json')).toHaveValue(/"acme_http01"/);
  await page.getByLabel('HTTP-01 listener IDs').fill('outside'); await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('listener'); expect(writes).toHaveLength(0);
  await page.getByLabel('HTTP-01 listener IDs').fill('edge'); await page.getByLabel('HTTP-01 issuer backend').fill('http://issuer:8080/admin'); await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('HTTP root'); expect(writes).toHaveLength(0);
});


test('route security predicates cannot be silently bypassed by HTTP-01 forwarding', async ({ page }) => {
  const { writes } = await fixture(page, { backend: 'http://issuer:8080' });
  await page.getByLabel('Denied CIDRs', { exact: true }).fill('192.0.2.0/24');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('CIDR denials');
  expect(writes).toHaveLength(0);
});


test('managed ACME permission is simple, default-on and keeps registration when off', async ({ page }) => {
  const original = { backend: 'docker://acme-issuer/edge/8080', listener_ids: ['edge'] };
  const { writes } = await fixture(page, original, false);
  const toggle = page.getByLabel('ACME allow'); await expect(toggle).toBeChecked();
  await expect(page.getByLabel('HTTP-01 issuer backend')).toBeHidden();
  await toggle.uncheck(); await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].acme_http01).toEqual({ ...original, allow: false });
});

test('unregistered default-on permission does not invent an issuer binding', async ({ page }) => {
  const { writes } = await fixture(page, null, false);
  await expect(page.getByLabel('ACME allow')).toBeChecked();
  await expect(page.getByLabel('HTTP-01 issuer backend')).toBeHidden();
  await page.getByLabel('Retries', { exact: true }).fill('1');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0]).not.toHaveProperty('acme_http01');
});
