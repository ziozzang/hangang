import { test, expect } from '@playwright/test';

test('actual native active-health edit validates, persists and requalifies', async ({ page, request }) => {
  const base = process.env.HANGANG_HEALTH_ACTUAL_BASE;
  test.skip(!base, 'Run with the owned tests/initial_health_smoke.py fixture.');
  const token = 'owned-first-check-token';
  const headers = { Authorization: `Bearer ${token}` };
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="http"]').click();
  await page.locator('[data-route-id="checked"]').getByRole('button', { name: 'Edit', exact: true }).click();
  const field = page.locator('#route-field-active_health_healthy_successes');
  const section = field.locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate(element => element.open))) await section.locator('summary').click();
  await expect(page.locator('#route-field-active_health_initial_state')).toHaveValue('checking');
  await field.fill('3');
  await page.locator('#route-dialog').getByRole('button', { name: 'Save route', exact: true }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  const config = await (await request.get(`${base}/v1/config`, { headers })).json();
  expect(config.http[0].balance.active_health.healthy_successes).toBe(3);
  expect(config.http[0].balance.active_health.initial_state).toBe('checking');
  await expect.poll(async () => {
    const result = await (await request.get(`${base}/v1/operations`, { headers })).json();
    return result.rows[0].initial_check_pending;
  }).toBe(false);
});
