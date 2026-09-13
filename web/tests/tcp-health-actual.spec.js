import { test, expect } from '@playwright/test';

test('actual TCP health policy can be edited and persisted through native UI', async ({ page, request }) => {
  const base = process.env.HANGANG_TCP_HEALTH_ACTUAL_BASE;
  test.skip(!base, 'Run with tests/tcp_health_smoke.py owned fixture.');
  const token = 'owned-tcp-health-token';
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="tcp"]').click();
  await page.locator('[data-route-id="checked-tcp"]').getByRole('button', { name: 'Edit', exact: true }).click();
  const field = page.locator('#route-field-tcp_health_healthy_successes');
  const section = field.locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate(element => element.open))) await section.locator('summary').click();
  await field.fill('3');
  await page.getByRole('button', { name: 'Save route', exact: true }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  const config = await (await request.get(`${base}/v1/config`, { headers: { Authorization: `Bearer ${token}` } })).json();
  expect(config.tcp[0].health.healthy_successes).toBe(3);
  expect(config.tcp[0].health.initial_state).toBe('checking');
});
