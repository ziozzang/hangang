import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_ACCESS_ACTUAL_BASE;
const token = process.env.HANGANG_ACCESS_ACTUAL_TOKEN;

test('actual protected route round-trip preserves authentication and Lua flexibility', async ({ page, request }) => {
  test.skip(!base || !token, 'Run with the owned tests/access_mode_smoke.py fixture.');
  const headers = { Authorization: `Bearer ${token}` };
  const beforeResponse = await request.get(`${base}/v1/config`, { headers });
  expect(beforeResponse.ok()).toBeTruthy();
  const before = await beforeResponse.json();
  const original = before.http.find(route => route.id === 'protected');
  expect(original.access_mode).toBe('protected');

  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  const metric = page.locator('.metric').filter({ has: page.locator('.metric-label', { hasText: /^Lua capacity rejections$/ }) });
  await expect(metric.locator('.metric-value')).toHaveText('0');
  const status = await (await request.get(`${base}/v1/status`, { headers })).json();
  expect(status.metrics.policy_capacity_rejections_total).toBe(0);
  const prometheus = await (await request.get(`${base}/metrics`, { headers })).text();
  expect(prometheus).toContain('hangang_policy_capacity_rejections_total 0\n');
  await page.locator('[data-view="http"]').click();
  await page.locator('[data-route-id="protected"]').getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.locator('#route-field-access_mode')).toHaveValue('protected');
  await page.locator('#route-dialog').getByRole('button', { name: 'Save route', exact: true }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();

  const afterResponse = await request.get(`${base}/v1/config`, { headers });
  expect(afterResponse.ok()).toBeTruthy();
  const after = await afterResponse.json();
  const saved = after.http.find(route => route.id === 'protected');
  expect(after.revision).toBe(before.revision + 1);
  expect(saved.access_mode).toBe('protected');
  expect(saved.basic_auth).toEqual(original.basic_auth);
  expect(saved.lua).toBe(original.lua);

  // Direct API bypass of the UI still cannot remove the declaration and auth.
  const downgraded = structuredClone(saved);
  delete downgraded.access_mode;
  downgraded.basic_auth = null;
  const rejected = await request.put(`${base}/v1/routes/http/protected`, {
    headers: { ...headers, 'If-Match': `"${after.revision}"` }, data: downgraded,
  });
  expect([400, 422]).toContain(rejected.status());
  const final = await (await request.get(`${base}/v1/config`, { headers })).json();
  expect(final.revision).toBe(after.revision);
  expect(final.http.find(route => route.id === 'protected')).toEqual(saved);
});

test('actual Lua editor uses nonce styles and saves a valid highlighted policy', async ({ page, request }) => {
  test.skip(!base || !token || !process.env.HANGANG_ACCESS_ACTUAL_PUBLIC, 'Run with the owned access-mode fixture.');
  const headers = { Authorization: `Bearer ${token}` };
  await page.addInitScript(() => {
    window.__editorCspViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.__editorCspViolations.push(event.violatedDirective));
  });
  const html = await request.get(`${base}/ui/`);
  const csp = html.headers()['content-security-policy'];
  expect(csp).toContain("script-src 'self';");
  expect(csp).toContain("style-src 'self' 'nonce-");
  expect(csp).not.toContain('unsafe-inline');
  expect(csp).not.toContain('unsafe-eval');
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="http"]').click();
  await page.locator('[data-route-id="protected"]').getByRole('button', { name: 'Edit', exact: true }).click();
  const section = page.locator('.cm-content[aria-label="Lua policy"]').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate(element => element.open))) await section.locator('summary').click();
  const editor = page.locator('.cm-content[aria-label="Lua policy"]');
  await expect(editor).toBeVisible();
  const script = 'local tag = "editor"\nhangang.set_header("x-app", tag)';
  await editor.fill(script);
  await expect(page.locator('#route-field-lua')).toHaveValue(script);
  await expect(section.locator('.cm-lineNumbers')).toContainText('2');
  const keyword = editor.locator('.cm-line span').filter({ hasText: /^local$/ });
  await expect(keyword).toBeVisible();
  expect(await keyword.evaluate(element => getComputedStyle(element).color))
    .not.toBe(await editor.evaluate(element => getComputedStyle(element).color));
  await expect.poll(async () => JSON.parse(await page.locator('#route-json').inputValue()).lua).toBe(script);
  expect(await page.evaluate(() => window.__editorCspViolations)).toEqual([]);
  const styleNonce = await page.locator('meta[name="csp-nonce"]').getAttribute('content');
  expect(styleNonce).toBeTruthy();
  expect(await page.locator('style').evaluateAll((styles, nonce) => styles.length > 0 && styles.every(style => style.nonce === nonce), styleNonce)).toBe(true);
  await page.locator('#route-dialog').getByRole('button', { name: 'Save route', exact: true }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  const saved = await (await request.get(`${base}/v1/config`, { headers })).json();
  expect(saved.http.find(route => route.id === 'protected').lua).toBe(script);
  const upstream = await request.get(`${process.env.HANGANG_ACCESS_ACTUAL_PUBLIC}/protected`, {
    headers: { Authorization: `Basic ${Buffer.from('alice:secret').toString('base64')}` },
  });
  expect(upstream.status()).toBe(200);
  expect(await upstream.text()).toBe('owned-origin');
  await expect(page.locator('.cm-editor')).toHaveCount(0);
});
