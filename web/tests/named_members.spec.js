import { test, expect } from '@playwright/test';

const http = {
  id: 'api', host: 'api.example.test', path_prefix: '/', headers: {}, json: {},
  backends: ['http://127.0.0.1:8080', 'http://127.0.0.1:8081'], deny_cidrs: [],
  balance: { mode: 'round_robin', weights: [3, 1], health: null },
};
const tcp = {
  id: 'stream', listen: '0.0.0.0:9001', sni: null,
  backends: ['127.0.0.1:8080', '127.0.0.1:8081'], deny_cidrs: [],
};

async function fixture(page, type, configured) {
  const writes = [];
  await page.route('**/*', (handled) => {
    const request = handled.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision: 3, http_routes: type === 'http' ? 1 : 0, tcp_routes: type === 'tcp' ? 1 : 0, uptime_seconds: 10, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === `/v1/routes/${type}/${configured.id}` && request.method() === 'PUT') {
      writes.push(request.postDataJSON());
      return handled.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === `/v1/routes/${type}/${configured.id}`) return handled.fulfill({ json: configured, headers: { etag: '"3"' } });
    if (path === `/v1/routes/${type}`) return handled.fulfill({ json: { revision: 3, routes: [configured] }, headers: { etag: '"3"' } });
    if (path === '/v1/config') return handled.fulfill({ json: { revision: 3, http: type === 'http' ? [configured] : [], tcp: type === 'tcp' ? [configured] : [] } });
    return handled.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.getByRole('link', { name: `${type.toUpperCase()} routes` }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
  return writes;
}

async function save(page) {
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
}

async function openAdvanced(page) {
  const details = page.locator('.advanced-editor');
  if (!(await details.evaluate((element) => element.open))) await details.locator('summary').click();
}

test('legacy HTTP strings and positional weights stay byte-for-byte shaped without conversion', async ({ page }) => {
  const writes = await fixture(page, 'http', http);
  await expect(page.locator('#route-field-backends')).toHaveValue(http.backends.join('\n'));
  await page.locator('#route-field-priority').fill('2');
  await save(page);
  expect(writes).toHaveLength(1);
  expect(writes[0].backends).toEqual(http.backends);
  expect(writes[0].balance.weights).toEqual([3, 1]);
});

test('explicit HTTP conversion creates IDs and transfers positional weights exactly once', async ({ page }) => {
  const writes = await fixture(page, 'http', http);
  await page.getByRole('button', { name: 'Convert to named members' }).click();
  const rows = page.locator('.backend-member-row');
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0).locator('.backend-member-id')).toHaveValue('member-1');
  await expect(rows.nth(0).locator('.backend-member-weight')).toHaveValue('3');
  await expect(page.locator('#route-field-balance_weights')).toBeDisabled();
  await rows.nth(1).locator('.backend-member-id').fill('green');
  await rows.nth(1).locator('.backend-member-weight').fill('5');
  await save(page);
  expect(writes).toHaveLength(1);
  expect(writes[0].backends).toEqual([
    { id: 'member-1', address: 'http://127.0.0.1:8080', weight: 3 },
    { id: 'green', address: 'http://127.0.0.1:8081', weight: 5 },
  ]);
  expect(writes[0].balance.weights).toEqual([]);
});

test('named HTTP edit and locale switch retain identity, serving marker and unknown route fields', async ({ page }) => {
  const configured = structuredClone(http);
  configured.backends = [
    { id: 'blue', address: 'http://127.0.0.1:8080', weight: 4, desired_state: 'serving' },
    { id: 'green', address: 'http://127.0.0.1:8081' },
  ];
  configured.balance.weights = [];
  configured.future_route_field = { retain: true };
  const writes = await fixture(page, 'http', configured);
  await page.locator('.backend-member-row').nth(0).locator('.backend-member-address').fill('http://127.0.0.1:9090');
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.locator('.backend-member-row').nth(0).locator('.backend-member-address')).toHaveValue('http://127.0.0.1:9090');
  await expect(page.getByRole('button', { name: '멤버 추가' })).toBeVisible();
  await page.locator('#route-field-priority').fill('7');
  await save(page);
  expect(writes).toHaveLength(1);
  expect(writes[0].backends).toEqual([
    { id: 'blue', address: 'http://127.0.0.1:9090', weight: 4, desired_state: 'serving' },
    { id: 'green', address: 'http://127.0.0.1:8081' },
  ]);
  expect(writes[0].future_route_field).toEqual({ retain: true });
});

test('advanced JSON named/legacy changes survive an unrelated native edit', async ({ page }) => {
  const writes = await fixture(page, 'http', http);
  const json = page.locator('#route-json');
  await openAdvanced(page);
  const named = structuredClone(http);
  named.backends = [{ id: 'blue', address: 'http://127.0.0.1:8080', weight: 3 }, { id: 'green', address: 'http://127.0.0.1:8081' }];
  named.balance.weights = [];
  named.future_route_field = { retain: true };
  await json.fill(JSON.stringify(named));
  await expect(page.locator('.backend-member-row')).toHaveCount(2);
  await page.locator('#route-field-priority').fill('4');
  await save(page);
  expect(writes[0].backends).toEqual(named.backends);
  expect(writes[0].future_route_field).toEqual({ retain: true });
});

test('native duplicate IDs and nonserving members fail closed without issuing a write', async ({ page }) => {
  const configured = structuredClone(http);
  configured.backends = [{ id: 'blue', address: 'http://127.0.0.1:8080' }, { id: 'green', address: 'http://127.0.0.1:8081' }];
  configured.balance.weights = [];
  const writes = await fixture(page, 'http', configured);
  await page.locator('.backend-member-row').nth(1).locator('.backend-member-id').fill('blue');
  await expect(page.locator('#route-message')).toContainText('Member IDs must be unique');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes).toHaveLength(0);
  const nonserving = structuredClone(configured); nonserving.backends[0].desired_state = 'draining';
  await openAdvanced(page);
  await page.locator('#route-json').fill(JSON.stringify(nonserving));
  await page.locator('#route-field-priority').fill('8');
  await expect(page.locator('#route-message')).toContainText('Only serving members');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes).toHaveLength(0);
});

test('TCP named editor changes weight, adds a member and retains object shape', async ({ page }) => {
  const configured = structuredClone(tcp);
  configured.backends = [{ id: 'blue', address: '127.0.0.1:8080', weight: 2 }, { id: 'green', address: '127.0.0.1:8081' }];
  const writes = await fixture(page, 'tcp', configured);
  await page.locator('.backend-member-row').nth(0).locator('.backend-member-weight').fill('6');
  await page.getByRole('button', { name: 'Add member' }).click();
  await expect(page.locator('.backend-member-row')).toHaveCount(3);
  await page.locator('.backend-member-row').nth(2).locator('.backend-member-address').fill('127.0.0.1:8082');
  await save(page);
  expect(writes).toHaveLength(1);
  expect(writes[0].backends).toEqual([
    { id: 'blue', address: '127.0.0.1:8080', weight: 6 },
    { id: 'green', address: '127.0.0.1:8081' },
    { id: 'member-1', address: '127.0.0.1:8082' },
  ]);
});

test('TCP reverse conversion refuses weight loss', async ({ page }) => {
  const configured = structuredClone(tcp);
  configured.backends = [{ id: 'blue', address: '127.0.0.1:8080', weight: 2 }];
  await fixture(page, 'tcp', configured);
  await page.getByRole('button', { name: 'Convert to legacy addresses' }).click();
  await expect(page.locator('#route-message')).toContainText('cannot be preserved');
  await expect(page.locator('.backend-member-row')).toHaveCount(1);
});

test('explicit HTTP reverse conversion restores positional weights without touching other route policy', async ({ page }) => {
  const configured = structuredClone(http);
  configured.backends = [
    { id: 'blue', address: 'http://127.0.0.1:8080', weight: 3 },
    { id: 'green', address: 'http://127.0.0.1:8081', weight: 5 },
  ];
  configured.balance.weights = [];
  configured.require_tls = true;
  const writes = await fixture(page, 'http', configured);
  await page.getByRole('button', { name: 'Convert to legacy addresses' }).click();
  await expect(page.locator('#route-field-backends')).toHaveValue(http.backends.join('\n'));
  await expect(page.locator('#route-field-balance_weights')).toHaveValue('3, 5');
  await save(page);
  expect(writes[0].backends).toEqual(http.backends);
  expect(writes[0].balance.weights).toEqual([3, 5]);
  expect(writes[0].require_tls).toBe(true);
});

test('mixed advanced backend arrays cannot be silently normalized by a later native edit', async ({ page }) => {
  const writes = await fixture(page, 'http', http);
  await openAdvanced(page);
  const mixed = structuredClone(http);
  mixed.backends[1] = { id: 'green', address: 'http://127.0.0.1:8081' };
  await page.locator('#route-json').fill(JSON.stringify(mixed));
  await page.locator('#route-field-priority').fill('3');
  await expect(page.locator('#route-message')).toContainText('all addresses or all named members');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  expect(JSON.parse(await page.locator('#route-json').inputValue()).backends).toEqual(mixed.backends);
});

test('removing a named member reindexes remaining drafts without losing explicit serving or weight', async ({ page }) => {
  const configured = structuredClone(http);
  configured.backends = [
    { id: 'blue', address: 'http://127.0.0.1:8080' },
    { id: 'green', address: 'http://127.0.0.1:8081', weight: 1, desired_state: 'serving' },
  ];
  configured.balance.weights = [];
  const writes = await fixture(page, 'http', configured);
  await page.locator('.backend-member-row').first().getByRole('button', { name: 'Remove member' }).click();
  await page.locator('.backend-member-row').first().locator('.backend-member-id').fill('green-renamed');
  await page.locator('#route-field-priority').fill('2');
  await save(page);
  expect(writes[0].backends).toEqual([
    { id: 'green-renamed', address: 'http://127.0.0.1:8081', weight: 1, desired_state: 'serving' },
  ]);
});
