import { test, expect } from '@playwright/test';

test('actual HTTP/TCP member editor converts, saves and exposes IDs with effective weights', async ({ page, request }) => {
  const base = process.env.HANGANG_NAMED_ACTUAL_BASE;
  test.skip(!base, 'Run with the owned tests/named_members_smoke.py fixture.');
  const headers = { Authorization: 'Bearer fixture-named-member-token' };
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill('fixture-named-member-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  for (const type of ['http', 'tcp']) {
    await page.locator(`[data-view="${type}"]`).click();
    await page.locator(`[data-route-id="${type}-named"]`).getByRole('button', { name: 'Edit', exact: true }).click();
    await page.getByRole('button', { name: 'Convert to named members', exact: true }).click();
    const rows = page.locator('.backend-member-row');
    await expect(rows).toHaveCount(2);
    await rows.nth(0).locator('.backend-member-id').fill('blue');
    await rows.nth(1).locator('.backend-member-id').fill('green');
    await rows.nth(0).locator('.backend-member-weight').fill('3');
    await rows.nth(1).locator('.backend-member-weight').fill(type === 'http' ? '2' : '1');
    await page.locator('#save-route').click();
    await expect(page.locator('#route-dialog')).toBeHidden();
    const config = await (await request.get(`${base}/v1/config`, { headers })).json();
    expect(config[type][0].backends.map(member => member.id)).toEqual(['blue', 'green']);
    if (type === 'http') expect(config.http[0].balance.weights).toEqual([]);
  }
  const operations = await (await request.get(`${base}/v1/operations`, { headers })).json();
  expect(operations.rows.map(row => row.member_id)).toEqual(['blue', 'green', 'blue', 'green']);
  expect(operations.rows.map(row => row.weight)).toEqual([3, 2, 3, 1]);
  await page.locator('[data-view="operations"]').click();
  await expect(page.locator('#operations-rows')).toContainText('blue');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#operations-rows')).toContainText('green');
});
