import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_RECORDING_ACTUAL_BASE;
const publicBase = process.env.HANGANG_RECORDING_ACTUAL_PUBLIC;
const token = process.env.HANGANG_RECORDING_ACTUAL_TOKEN;

test('embedded recording editor changes real forwarding observations and persists its removal', async ({ page, request }) => {
  test.skip(!base || !publicBase || !token, 'Run with owned tests/http_recording_smoke.py.');
  const headers = { Authorization: `Bearer ${token}` };
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible())
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  // Qualify the embedded diagnostics against actual backend fields, not only mocked UI data.
  const liveStatus = await (await request.get(`${base}/v1/status`, { headers })).json();
  const diagnostics = page.locator('#security-diagnostics-grid [data-metric]');
  await expect(diagnostics).toHaveCount(9);
  for (const row of await diagnostics.all()) {
    const field = await row.getAttribute('data-metric');
    expect(liveStatus.metrics[field]).toBe(0);
    await expect(row.locator('strong')).toHaveText('0');
  }
  await page.locator('[data-view="config"]').click();
  const section = page.locator('#http-recording-section');
  if (!(await section.evaluate(element => element.open))) await section.locator('summary').click();
  await page.locator('#http-recording-enabled').check();
  await page.locator('#http-recording-default').selectOption('drop');
  await page.locator('#http-recording-add').click();
  const card = page.locator('#http-recording-rules .user-card').first();
  await card.getByLabel('Rule ID').fill('keep');
  await card.getByLabel('Path prefixes (one per line)').fill('/keep-');
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Revision 1 is active');
  for (const path of ['/hidden-recording-fixture', '/keep-recording-fixture?token=query-recording-fixture']) {
    const response = await request.get(`${publicBase}${path}`);
    expect(response.status()).toBe(200);
    expect(await response.text()).toBe('owned-http-recording-origin');
  }
  const batch = await (await request.get(`${base}/v1/traffic`, { headers })).json();
  expect(batch.filtered_total).toBe(1);
  expect(batch.records).toHaveLength(1);
  expect(batch.records[0]).toMatchObject({ path: '/keep-recording-fixture', policy_revision: 1 });
  await page.locator('#http-recording-enabled').uncheck();
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Revision 2 is active');
  expect((await request.get(`${publicBase}/restored-recording-fixture`)).status()).toBe(200);
  const restored = await (await request.get(`${base}/v1/traffic`, { headers })).json();
  expect(restored.filtered_total).toBe(1);
  expect(restored.records).toHaveLength(2);
  expect(restored.records.at(-1)).toMatchObject({ path: '/restored-recording-fixture', policy_revision: 2 });
});
