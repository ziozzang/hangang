import { test, expect } from '@playwright/test';

const admin = process.env.HANGANG_PUBLIC_ACTUAL_ADMIN;
const defaultBase = process.env.HANGANG_PUBLIC_ACTUAL_DEFAULT;
const edgeBase = process.env.HANGANG_PUBLIC_ACTUAL_EDGE;
const occupied = process.env.HANGANG_PUBLIC_ACTUAL_OCCUPIED;
const token = process.env.HANGANG_PUBLIC_ACTUAL_TOKEN;

test('embedded public listener controls publish scoped forwarding and retain active revision on bind failure', async ({ page, request }) => {
  test.skip(!admin || !defaultBase || !edgeBase || !occupied || !token, 'Run with owned tests/public_listener_smoke.py.');
  const headers = { Authorization: `Bearer ${token}` };
  const config = async () => (await request.get(`${admin}/v1/config`, { headers })).json();
  const forwarded = async (base, path) => {
    const response = await request.get(`${base}${path}`, { timeout: 3000 });
    return [response.status(), await response.text()];
  };
  const notAccepting = async (base) => {
    try { return (await request.get(`${base}/scoped`, { timeout: 1000 })).status() !== 200; }
    catch { return true; }
  };
  await page.goto(`${admin}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible())
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  expect((await config()).revision).toBe(0);
  await page.locator('[data-view="config"]').click();
  const panel = page.locator('#public-http-panel');
  if (!(await panel.evaluate(element => element.open))) await panel.locator('summary').click();
  await panel.getByRole('button', { name: 'Add public listener' }).click();
  const form = page.locator('#public-http-form');
  await form.locator('#public-http-id').fill('edge');
  await form.locator('#public-http-listen').fill(new URL(edgeBase).host);
  await expect(form.locator('#public-http-trusted_proxy_cidrs')).toHaveValue('');
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await page.locator('#apply-config').click();
  await expect.poll(async () => (await config()).revision).toBe(1);
  expect((await config()).public_http[0]).toMatchObject({ id: 'edge', listen: new URL(edgeBase).host });
  expect((await config()).public_http[0].certificates || []).toEqual([]);
  expect((await config()).public_http[0].trusted_proxy_cidrs || []).toEqual([]);
  expect((await forwarded(defaultBase, '/scoped'))[0]).toBe(200);
  expect((await forwarded(defaultBase, '/legacy'))[0]).toBe(200);
  expect((await forwarded(edgeBase, '/scoped'))[0]).toBe(404);
  expect((await forwarded(edgeBase, '/legacy'))[0]).toBe(404);

  await page.locator('[data-view="http"]').click();
  await page.locator('[data-route-id="scoped"]').getByRole('button', { name: 'Edit' }).click();
  const ids = page.locator('#route-form [name="listener_ids"]');
  const section = ids.locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate(element => element.open))) await section.locator('summary').click();
  await ids.fill('default\nedge');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect.poll(async () => (await config()).revision).toBe(2);
  expect((await config()).http.find(route => route.id === 'scoped').listener_ids).toEqual(['default', 'edge']);
  expect(await forwarded(defaultBase, '/scoped')).toEqual([200, 'owned-public-listener-origin:/scoped']);
  expect(await forwarded(edgeBase, '/scoped')).toEqual([200, 'owned-public-listener-origin:/scoped']);
  expect((await forwarded(edgeBase, '/legacy'))[0]).toBe(404);

  await page.locator('[data-view="config"]').click();
  await panel.getByRole('button', { name: 'Deactivate' }).click();
  await page.locator('#apply-config').click();
  await expect.poll(async () => (await config()).revision).toBe(3);
  await expect.poll(() => notAccepting(edgeBase)).toBe(true);
  expect((await forwarded(defaultBase, '/scoped'))[0]).toBe(200);
  await panel.getByRole('button', { name: 'Activate' }).click();
  await page.locator('#apply-config').click();
  await expect.poll(async () => (await config()).revision).toBe(4);
  await expect.poll(async () => (await forwarded(edgeBase, '/scoped'))[0]).toBe(200);

  await panel.getByRole('button', { name: 'Edit' }).click();
  await form.locator('#public-http-listen').fill(occupied);
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText(/bind|address|listener|사용 중|주소/i);
  expect((await config()).revision).toBe(4);
  expect((await config()).public_http[0].listen).toBe(new URL(edgeBase).host);
  expect((await forwarded(edgeBase, '/scoped'))[0]).toBe(200);
});
