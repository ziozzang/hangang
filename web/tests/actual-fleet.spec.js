import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_FLEET_ACTUAL_BASE;
const token = process.env.HANGANG_FLEET_ACTUAL_TOKEN;

test('native fleet UI matches three owned HTTPS peers without browser-held machine credentials', async ({ page, request }) => {
  test.skip(!base || !token, 'Requires the owned HTTPS collector fixture.');
  const response = await request.get(`${base}/v1/fleet/observations`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.status()).toBe(200);
  const snapshot = await response.json();
  expect(snapshot.expected_nodes).toBe(3);
  expect(snapshot.fresh_nodes).toBe(1);
  expect(Object.fromEntries(snapshot.nodes.map(row => [row.node_id, [row.group_id, row.role]]))).toEqual({
    'good-edge': ['edge-a', 'gateway'], 'expected-edge': ['edge-b', 'gateway'], 'tls-edge': [null, null],
  });
  const mutations = [];
  const peerRequests = [];
  page.on('request', req => {
    const url = new URL(req.url());
    if (url.pathname.startsWith('/v1/') && req.method() !== 'GET') mutations.push(req.method());
    if (url.pathname === '/v1/fleet/observation') peerRequests.push(req.url());
  });
  await page.goto(`${base}/ui/`);
  if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
    await page.getByRole('button', { name: 'Use administrator token' }).click();
  }
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#connection-state')).toHaveText('Connected');
  await page.locator('[data-view="operations"]').click();
  await expect(page.locator('#fleet-observations-coverage')).toHaveText('1 of 3 fresh');
  await expect(page.locator('#fleet-observations-process')).toHaveText(snapshot.observer_instance_id);
  const rows = page.locator('#fleet-observations-rows tr');
  await expect(rows).toHaveCount(3);
  for (const expected of snapshot.nodes) {
    const row = rows.filter({ has: page.locator('td:first-child > strong', { hasText: new RegExp(`^${expected.node_id}$`) }) });
    await expect(row).toContainText(expected.endpoint);
    await expect(row).toContainText(`Inventory group: ${expected.group_id ?? 'Unassigned'}`);
    await expect(row).toContainText(`Inventory role: ${expected.role ?? 'Unassigned'}`);
    if (expected.observation) {
      await expect(row).toContainText(expected.observation.instance_id);
      await expect(row).toContainText(expected.observation.config_digest);
    }
  }
  await expect(rows.filter({ hasText: 'expected-edge' })).toContainText('Identity mismatch');
  await expect(rows.filter({ hasText: 'tls-edge' })).toContainText('Unavailable');
  await page.locator('#fleet-observations-group').selectOption('group:edge-a');
  await expect(rows).toHaveCount(1);
  await expect(page.locator('#fleet-observations-selected-coverage')).toHaveText('Selected reporting: 1 of 1 fresh');
  await expect(page.locator('#fleet-observations-coverage')).toHaveText('1 of 3 fresh');
  await page.locator('#fleet-observations-group').selectOption('group:edge-b');
  await expect(rows).toHaveCount(1);
  await expect(page.locator('#fleet-observations-selected-coverage')).toHaveText('Selected reporting: 0 of 1 fresh');
  await page.locator('#fleet-observations-group').selectOption('ungrouped');
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText('tls-edge');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#fleet-observations-title')).not.toHaveText('Fleet observations');
  await page.locator('#fleet-observations-refresh').click();
  await expect(rows).toHaveCount(1);
  await expect(page.locator('#fleet-observations-group')).toHaveValue('ungrouped');
  await expect(page.locator('#fleet-observations-process')).toHaveText(snapshot.observer_instance_id);
  expect(mutations).toEqual([]);
  expect(peerRequests).toEqual([]);
});
