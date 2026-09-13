import { test, expect } from '@playwright/test';

async function fixture(page, { type = 'http', result = 204, locale = 'en' } = {}) {
  let present = true; const deletes = [];
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 1, tcp_routes: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === `/v1/routes/${type}`) return route.fulfill({ headers: { etag: '"7"' }, json: { revision: 7,
      routes: present ? [{ id: 'selected', path_prefix: '/', listen: '127.0.0.1:19001', backends: [type === 'http' ? 'http://127.0.0.1:9' : '127.0.0.1:9'] }] : [] } });
    if (path === `/v1/routes/${type}/selected` && request.method() === 'DELETE') {
      deletes.push(request.headers());
      if (result === 204) { present = false; return route.fulfill({ status: 204, headers: { etag: '"8"' } }); }
      return route.fulfill({ status: result, json: { title: result === 409 ? 'Revision Conflict' : 'Configuration Rejected', detail: result === 409 ? 'revision changed' : 'resource scope must first be released' } });
    }
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/'); await page.locator('#token-input').fill('fixture-token'); await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator(`[data-view="${type}"]`).click();
  const remove = page.locator(`#${type}-routes [data-route-id="selected"] .route-delete`);
  await expect(remove).toBeVisible();
  return { deletes, remove };
}

for (const type of ['http', 'tcp']) test(`${type} list deletes with confirmation and held revision without opening editor`, async ({ page }) => {
  const { deletes, remove } = await fixture(page, { type });
  await remove.click();
  await expect(page.locator('#confirm-message')).toContainText('selected');
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(deletes).toHaveLength(0);
  await page.locator('#confirm-accept').click();
  await expect(page.locator(`#${type}-routes [data-route-id="selected"]`)).toHaveCount(0);
  expect(deletes).toHaveLength(1); expect(deletes[0]['if-match']).toBe('"7"');
});

test('cancel list deletion preserves row and sends no mutation', async ({ page }) => {
  const { deletes, remove } = await fixture(page);
  await remove.click(); await page.locator('#confirm-dialog button[value="cancel"]').click();
  await expect(remove).toBeEnabled(); expect(deletes).toHaveLength(0);
});

for (const result of [409, 422]) test(`list deletion preserves row and exposes server rejection ${result}`, async ({ page }) => {
  const { deletes, remove } = await fixture(page, { result });
  await remove.click(); await page.locator('#confirm-accept').click();
  await expect(page.locator('#global-alert')).toContainText(result === 409 ? 'confirm deletion again' : 'resource scope must first be released');
  await expect(page.locator('#http-routes [data-route-id="selected"]')).toBeVisible();
  expect(deletes).toHaveLength(1);
});

test('Korean inventory exposes deletion without editing', async ({ page }) => {
  const { remove } = await fixture(page, { locale: 'ko' });
  await expect(remove).toHaveText('삭제');
  await remove.click(); await expect(page.locator('#confirm-accept')).toHaveText('삭제');
});
