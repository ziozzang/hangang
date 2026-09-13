import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_ACTUAL_BASE;
const token = process.env.HANGANG_ACTUAL_TOKEN;
const enabled = process.env.HANGANG_CERT_ACTUAL === '1';

test('owned issuer and admin relay expose certificate metadata and preserve route, cache, and certificate activation', async ({ page, request }) => {
  test.skip(!enabled || !base || !token, 'Run only with the owned certificate console fixture.');
  test.setTimeout(60000);
  expect(new URL(base).hostname).toBe('127.0.0.1');
  const headers = { Authorization: `Bearer ${token}` };
  const getConfig = async () => {
    const response = await request.get(`${base}/v1/config`, { headers });
    expect(response.status()).toBe(200);
    return { data: await response.json(), etag: response.headers().etag };
  };
  const initial = await getConfig();
  expect(initial.data.http).toEqual([]);
  expect(initial.data.tcp).toEqual([]);
  expect(initial.data.cache ?? null).toBeNull();
  expect(initial.data.certificates).toHaveLength(1);
  expect(initial.data.certificates[0].id).toBe('managed-fixture');
  expect(initial.data.certificates[0]).toMatchObject({ hosts: ['example.test', 'www.example.test'], issuer_status_file: expect.stringMatching(/^\//) });
  const inventoryResponse = await request.get(`${base}/v1/certificates?offset=0&limit=32`, { headers });
  expect(inventoryResponse.status()).toBe(200);
  const inventory = await inventoryResponse.json();
  expect(inventory.certificates[0]).toMatchObject({ id: 'managed-fixture', source: 'standalone_acme', read_state: 'ok', enabled: true, tls_binding: 'configured' });
  expect(inventory.certificates[0].san_dns).toEqual(expect.arrayContaining(['example.test', 'www.example.test']));
  expect(inventory.certificates[0].not_after_unix_ms).toBeGreaterThan(inventory.server_time_unix_ms);

  const routeId = 'certificate-console-fixture';
  try {
    await page.goto(`${base}/ui/`);
    if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) await page.getByRole('button', { name: 'Use administrator token' }).click();
    await page.getByLabel('Administrator token').fill(token);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#connection-state')).toHaveText('Connected');

    await page.getByRole('link', { name: 'Certificates' }).click();
    const certificateList = page.locator('#certificate-list');
    const certificateInventory = page.locator('#certificate-inventory');
    await expect(certificateInventory).toContainText('ACME-managed file references (1)');
    await expect(certificateInventory).toContainText('www.example.test');
    await expect(certificateInventory).toContainText('Valid by certificate dates');
    await expect(certificateInventory).toContainText('Issuer-reported: ready');
    // Reapplying the fetched document must preserve the ACME registration
    // manifest. Default certificates with empty SNI hosts have a separate fixture regression.
    await page.locator('#format-certificates').click();
    expect(JSON.parse(await page.locator('#certificate-editor').inputValue())).toEqual(initial.data.certificates);
    await page.getByRole('button', { name: 'Apply certificates' }).click();
    await expect(page.locator('#certificate-message')).toContainText('Certificate paths are active in revision');
    expect((await getConfig()).data.certificates).toEqual(initial.data.certificates);
    await certificateList.getByRole('button', { name: 'Deactivate' }).click();
    await expect(certificateList).toContainText('Disabled');
    expect((await getConfig()).data.certificates[0].enabled).toBe(false);
    await certificateList.getByRole('button', { name: 'Activate' }).click();
    await expect(certificateList).toContainText('Enabled');
    expect((await getConfig()).data.certificates[0].enabled ?? true).toBe(true);

    await page.getByRole('link', { name: 'Cache', exact: true }).click();
    const policy = { memory: { max_bytes: 1048576, max_entries: 64, eviction: 'lru' }, disk: null, max_object_bytes: 262144, max_fills: 4, fill_timeout_ms: 1000 };
    await page.getByLabel('Global cache policy JSON').fill(JSON.stringify(policy));
    await page.getByRole('button', { name: 'Apply cache policy' }).click();
    await expect(page.locator('#cache-message')).toContainText('Cache policy is active');
    await page.locator('#toggle-cache-policy').click();
    await expect(page.locator('#cache-state')).toHaveText('Disabled');
    expect((await getConfig()).data.cache).toMatchObject({ enabled: false, memory: policy.memory });
    await page.locator('#toggle-cache-policy').click();
    await expect(page.locator('#cache-state')).toHaveText('Enabled');

    await page.getByRole('link', { name: 'HTTP routes' }).click();
    await page.locator('#view-http > .page-head').getByRole('button', { name: 'New HTTP route' }).click();
    await page.getByLabel('Route ID').fill(routeId);
    await page.getByLabel('Backends').fill('http://127.0.0.1:65534');
    await page.getByRole('button', { name: 'Create route' }).click();
    await expect(page.getByText(`${routeId} created.`)).toBeVisible();
    const row = page.locator(`#http-routes tr[data-route-id="${routeId}"]`);
    await row.getByRole('button', { name: 'Deactivate' }).click();
    await expect(row).toContainText('Disabled');
    const disabled = await request.get(`${base}/v1/routes/http/${routeId}`, { headers });
    expect((await disabled.json()).enabled).toBe(false);
    await row.getByRole('button', { name: 'Activate' }).click();
    await expect(row).toContainText('Enabled');
    const active = await request.get(`${base}/v1/routes/http/${routeId}`, { headers });
    expect((await active.json()).enabled ?? true).toBe(true);
  } finally {
    // This test is only enabled for an owned fixture, but still restores each
    // published setting even when an assertion or browser step fails.
    const current = await getConfig();
    const restored = structuredClone(current.data);
    restored.cache = initial.data.cache ?? null;
    const fixture = restored.certificates.find(item => item.id === 'managed-fixture');
    if (fixture) delete fixture.enabled;
    const needsConfigRestore = JSON.stringify(restored.cache) !== JSON.stringify(current.data.cache)
      || current.data.certificates.some(item => item.id === 'managed-fixture' && item.enabled === false);
    if (needsConfigRestore) {
      const response = await request.put(`${base}/v1/config`, { headers: { ...headers, 'If-Match': current.etag }, data: restored });
      expect(response.status()).toBe(200);
    }
    const routes = await request.get(`${base}/v1/routes/http`, { headers });
    if (routes.ok() && (await routes.json()).routes.some(item => item.id === routeId)) {
      const response = await request.delete(`${base}/v1/routes/http/${routeId}`, { headers: { ...headers, 'If-Match': routes.headers().etag } });
      expect(response.ok()).toBeTruthy();
    }
  }
});
