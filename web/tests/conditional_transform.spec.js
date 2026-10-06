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

test('literal response prefix round-trips exactly and rejects streaming or oversized drafts', async ({ page }) => {
  const { writes } = await fixture(page);
  const toggle = page.locator('[name="response_transform_enabled"]');
  const panel = toggle.locator('xpath=ancestor::details[1]'); await panel.locator(':scope > summary').click(); await toggle.check();
  const prefix = page.locator('[name="response_transform_when_prefix"]');
  await prefix.fill('  window.bootstrap =');
  await page.locator('[name="response_transform_mode"]').selectOption('lines');
  await page.locator('#save-route').click(); await expect(page.locator('#route-message')).toContainText('buffered'); expect(writes).toHaveLength(0);
  await page.locator('[name="response_transform_mode"]').selectOption('buffered');
  await prefix.fill('한'.repeat(342)); await page.locator('#save-route').click(); await expect(page.locator('#route-message')).toContainText('1,024'); expect(writes).toHaveLength(0);
  await prefix.fill('  window.bootstrap =');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].response_transform.when_prefix).toBe('  window.bootstrap ='); expect(writes[0].future_policy).toEqual({ preserved: true });
});

test('advanced request prefix is rejected and response prefix survives NUL', async ({ page }) => {
  const { writes } = await fixture(page);
  const draft = JSON.parse(await page.locator('#route-json').inputValue());
  draft.request_transform = { mode: 'buffered', when_prefix: 'bootstrap', operations: [] };
  const jsonPanel = page.locator('#route-json').locator('xpath=ancestor::details[1]'); await jsonPanel.locator(':scope > summary').click();
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await page.getByLabel('Retries', { exact: true }).fill('1');
  await page.locator('#save-route').click(); await expect(page.locator('#route-message')).toContainText('response'); expect(writes).toHaveLength(0);
  delete draft.request_transform; draft.response_transform = { mode: 'buffered', when_prefix: ' \u0000bootstrap\n', operations: [] };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await page.getByLabel('Retries', { exact: true }).fill('2');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].response_transform.when_prefix).toBe(' \u0000bootstrap\n');
});
