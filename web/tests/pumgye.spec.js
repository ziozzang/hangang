import { test, expect } from '@playwright/test';

async function setup(page, { scope = '"3"', delayed = false, source = 'native', sourceState = 'native', healthy = true } = {}) {
  const calls = [];
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let document = { revision: 7, policy: { version: 1, information_classes: ['internal'], services: {
    orders: { permissions: ['read'], roles: { reader: { permissions: ['read'], information_classes: ['internal'] } },
      users: { 'fixture-user': ['reader'] }, networks: [{ cidr: '192.0.2.0/24', roles: ['reader'] }], require_guard: true },
  } } };
  await page.route('**/*', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    calls.push({ path, method: request.method(), headers: request.headers(), body: request.postDataJSON?.() });
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (path === '/v1/auth/logout') return route.fulfill({ status: 204, body: '' });
    if (path === '/v1/status') return route.fulfill({ json: { revision: 3, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {} } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 3, http: [], tcp: [], pumgye_authority: {
      decision_address: '127.0.0.1:9085', management_address: '127.0.0.1:9084',
      decision_token_env: 'PUMGYE_DECISION_TOKEN', admin_token_env: 'PUMGYE_ADMIN_TOKEN',
    } } });
    if (path === '/v1/pumgye/policy') {
      if (request.method() === 'GET' && delayed) await gate;
      if (request.method() === 'PUT') document = { ...request.postDataJSON(), revision: document.revision + 1 };
      const headers = { etag: `"${document.revision}"` }; if (scope) headers['x-hangang-config-revision'] = scope;
      return route.fulfill({ json: document, headers });
    }
    if (path === '/v1/pumgye/status') return route.fulfill({ json: { healthy, source_state: sourceState, source_lease_remaining_ms: source === 'kubernetes' ? 0 : null, policy_source: source, policy_revision: document.revision, decision_queries: 42 } });
    if (path === '/v1/pumgye/audit') return route.fulfill({ json: [{ revision: document.revision, actor: 'mtls:fixture-node', sha256: 'a'.repeat(64) }] });
    return route.fulfill({ status: 404, body: '' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-admin-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('.sidebar a[data-view="pumgye"]').click();
  return { calls, release };
}

test('independent policy publication targets owning authority and binds both revisions', async ({ page }) => {
  const { calls } = await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await expect(page.locator('#pumgye-authority-panel')).toBeVisible();
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('Observe mode or unavailable evidence refuses access.');
  await expect(page.locator('#pumgye-authority-status')).toContainText('"policy_revision": 7');
  await page.locator('#pumgye-subject').fill('new-guest');
  await page.locator('#pumgye-assignment-form button').click();
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(3);
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText('Authorization policy published.');
  const write = calls.find(call => call.path === '/v1/pumgye/policy' && call.method === 'PUT');
  expect(write.headers['if-match']).toBe('"7"');
  expect(write.headers['x-hangang-config-revision']).toBe('"3"');
  expect(write.body.policy.services.orders.users['new-guest']).toEqual(['guest']);
  expect(write.body.revision).toBe(7);
  expect(write.body.http).toBeUndefined();
  expect(calls.some(call => call.path === '/v1/config' && call.method === 'PUT')).toBe(false);
  await page.locator('#logout-button').click();
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-audit')).toHaveText('');
  await expect(page.locator('#pumgye-guard-requirement')).toHaveText('');
});

test('missing owning authority scope prevents publication', async ({ page }) => {
  const { calls } = await setup(page, { scope: null });
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText('Reload before publishing.');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});

test('late authority result cannot restore policy or audit after logout', async ({ page }) => {
  const { release } = await setup(page, { delayed: true });
  await page.locator('#logout-button').click();
  release();
  await page.waitForTimeout(150);
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(0);
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-audit')).toHaveText('');
});


test('Kubernetes source policy remains inspectable but cannot be edited or published', async ({ page }) => {
  const { calls } = await setup(page, { source: 'kubernetes' });
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await expect(page.locator('#pumgye-message')).toContainText('Kubernetes owns this policy.');
  await expect(page.locator('#pumgye-document')).toHaveAttribute('readonly', '');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await expect(page.locator('#pumgye-subject')).toBeDisabled();
  await expect(page.locator('#pumgye-new-service')).toBeDisabled();
  for (const button of await page.locator('#pumgye-matrix button').all()) await expect(button).toBeDisabled();
  await page.locator('#pumgye-publish').dispatchEvent('click');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});


test('expired Kubernetes authority is explicit and its persisted matrix stays read-only', async ({ page }) => {
  const { calls } = await setup(page, { source: 'kubernetes', sourceState: 'expired', healthy: false });
  await expect(page.locator('#pumgye-source-summary')).toContainText('Kubernetes source expired');
  await expect(page.locator('#pumgye-source-summary')).toContainText('Authority unavailable');
  await expect(page.locator('#pumgye-source-summary')).toContainText('Applied policy revision 7');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await page.route('**/v1/pumgye/status', route => route.fulfill({ status: 503, json: { error: 'unavailable' } }));
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-source-summary')).toHaveText('Authority unavailable');
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});

test('unreported policy ownership never enables database edits', async ({ page }) => {
  const { calls } = await setup(page, { source: undefined, sourceState: 'starting', healthy: false });
  // An unknown explicit source is also not a native authority.
  await page.route('**/v1/pumgye/status', route => route.fulfill({ json: { healthy: false, policy_revision: 7 } }));
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-source-summary')).toContainText('Source state unreported');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await page.locator('#pumgye-publish').dispatchEvent('click');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});


test('service guard requirement follows policy drafts and language changes', async ({ page }) => {
  await setup(page);
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('Observe mode');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('관찰 모드');
  const policy = JSON.parse(await page.locator('#pumgye-document').inputValue());
  policy.services.orders.require_guard = false;
  await page.locator('#pumgye-document').fill(JSON.stringify(policy));
  await page.locator('#pumgye-document').dispatchEvent('change');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('필수가 아닙니다');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('explicit network denial refuses access.');
});
