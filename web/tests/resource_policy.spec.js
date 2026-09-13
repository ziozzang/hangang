import { test, expect } from '@playwright/test';

const credential = `alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`;
const protectedRoute = {
  id: 'resource', access_mode: 'protected', host: 'api.example.test', path_prefix: '/v1',
  backends: ['http://127.0.0.1:8080'], auth: null,
  basic_auth: { realm: 'restricted', credentials: [credential], hide_credentials: true, identity_header: null },
};

async function fixture(page, initial = protectedRoute, locale = 'en') {
  const routes = new Map([[initial.id, structuredClone(initial)]]);
  const writes = [];
  let revision = 7;
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: routes.size, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') return handled.fulfill({ json: { revision, http: [...routes.values()], tcp: [], certificates: [] }, headers: { etag: `"${revision}"` } });
    if (path === '/v1/routes/http') {
      if (request.method() === 'POST') {
        const body = request.postDataJSON(); writes.push(body); routes.set(body.id, body); revision++;
        return handled.fulfill({ status: 201, json: { revision }, headers: { etag: `"${revision}"` } });
      }
      return handled.fulfill({ json: { revision, routes: [...routes.values()] }, headers: { etag: `"${revision}"` } });
    }
    if (path.startsWith('/v1/routes/http/')) {
      const id = decodeURIComponent(path.slice('/v1/routes/http/'.length));
      if (request.method() === 'PUT') {
        const body = request.postDataJSON(); writes.push(body); routes.set(id, body); revision++;
        return handled.fulfill({ json: { revision }, headers: { etag: `"${revision}"` } });
      }
      return handled.fulfill({ json: routes.get(id), headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/routes/tcp') return handled.fulfill({ json: { revision, routes: [] }, headers: { etag: `"${revision}"` } });
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="http"]').click();
  return { writes, routes };
}

async function edit(page, id = 'resource') {
  await page.locator(`[data-route-id="${id}"]`).getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function revealPolicy(page) {
  const section = page.locator('#route-field-resource_policy_action').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

async function save(page) {
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
}

test('Basic resource policy writes native exact allow rules and keeps default enforce omitted', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await revealPolicy(page);
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_id').fill('records.v1');
  await page.locator('.resource-rule-add').click();
  await page.locator('.resource-rule-subjects').fill('alice\nbob');
  await page.locator('.resource-rule-methods').fill('GET\nPOST');
  await save(page);
  expect(writes).toHaveLength(1);
  expect(writes[0].resource_policy).toEqual({
    resource_id: 'records.v1', principal: { source: 'basic' },
    allow: [{ subjects: ['alice', 'bob'], methods: ['GET', 'POST'] }],
  });
});

test('disabled enforced route needs an Off publication before explicit policy removal', async ({ page }) => {
  const configured = structuredClone(protectedRoute);
  configured.enabled = false;
  configured.resource_policy = { resource_id: 'records', principal: { source: 'basic' }, allow: [{ subjects: ['alice'], methods: ['GET'] }] };
  const { writes } = await fixture(page, configured);
  await edit(page);
  await revealPolicy(page);
  await page.locator('#route-field-resource_policy_action').selectOption('remove');
  await expect(page.locator('#route-message')).toContainText('Save enforcement Off first');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_enforce').uncheck();
  await save(page);
  expect(writes[0].enabled).toBe(false);
  expect(writes[0].resource_policy.enforce).toBe(false);
  await edit(page);
  await page.locator('#route-field-resource_policy_action').selectOption('remove');
  await save(page);
  expect(writes[1]).not.toHaveProperty('resource_policy');
  expect(writes[1].enabled).toBe(false);
});

test('external principal requires a copied identity header and denies empty allowlist by default', async ({ page }) => {
  const configured = structuredClone(protectedRoute);
  configured.basic_auth = null;
  configured.auth = { url: 'https://auth.example.test/check', response_headers: ['x-forwarded-user'] };
  const { writes } = await fixture(page, configured);
  await edit(page);
  await revealPolicy(page);
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_id').fill('records');
  await page.locator('#route-field-resource_policy_source').selectOption('external');
  await page.locator('#route-field-resource_policy_subject_header').fill('x-forwarded-email');
  await expect(page.locator('#route-message')).toContainText('must be in Identity response headers');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  await page.locator('#route-field-resource_policy_subject_header').fill('x-forwarded-user');
  await save(page);
  expect(writes[0].resource_policy).toEqual({
    resource_id: 'records', principal: { source: 'external', subject_header: 'x-forwarded-user' }, allow: [],
  });
});

test('advanced JSON policy and Korean locale round-trip through unrelated native edits', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  const advanced = page.locator('.advanced-editor');
  await advanced.locator('summary').click();
  const draft = structuredClone(protectedRoute);
  draft.resource_policy = { resource_id: 'acct', enforce: false, principal: { source: 'basic' }, allow: [{ subjects: ['앨리스'], methods: ['*'] }] };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-resource_policy_action')).toHaveValue('configured');
  await expect(page.locator('.resource-rule-subjects')).toHaveValue('앨리스');
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.locator('label[for="route-field-resource_policy_id"]')).toHaveText('리소스 ID');
  await page.locator('#route-field-priority').fill('3');
  await save(page);
  expect(writes[0].resource_policy).toEqual(draft.resource_policy);
});

test('invalid exact subjects and methods cannot be normalized into a write', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await revealPolicy(page);
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_id').fill('acct');
  await page.locator('.resource-rule-add').click();
  await page.locator('.resource-rule-subjects').fill(' alice');
  await page.locator('.resource-rule-methods').fill('get');
  await expect(page.locator('#route-message')).toContainText('Subjects must be exact');
  await page.locator('.resource-rule-subjects').fill('alice');
  await expect(page.locator('#route-message')).toContainText('Methods must be uppercase');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('advanced JSON cannot erase an enforced policy while editing an unrelated native field', async ({ page }) => {
  const configured = structuredClone(protectedRoute);
  configured.enabled = false;
  configured.resource_policy = { resource_id: 'records', principal: { source: 'basic' }, allow: [] };
  const { writes } = await fixture(page, configured);
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const dropped = structuredClone(configured); delete dropped.resource_policy;
  await page.locator('#route-json').fill(JSON.stringify(dropped));
  await page.locator('#route-field-priority').fill('5');
  await expect(page.locator('#route-message')).toContainText('Save enforcement Off first');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('malformed advanced policy rules cannot be normalized into an empty allowlist', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const malformed = structuredClone(protectedRoute);
  malformed.resource_policy = { resource_id: 'records', principal: { source: 'basic' }, allow: [{ subjects: 'alice', methods: ['GET'] }] };
  await page.locator('#route-json').fill(JSON.stringify(malformed));
  await page.locator('#route-field-priority').fill('2');
  await expect(page.locator('#route-message')).toContainText('Advanced resource policy JSON must contain');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  expect(JSON.parse(await page.locator('#route-json').inputValue()).resource_policy.allow[0].subjects).toBe('alice');
});

test('unenforced policies still require matching auth and reject terminal external responses', async ({ page }) => {
  const configured = structuredClone(protectedRoute);
  configured.auth = { url: 'https://auth.example.test/check', response_headers: ['x-forwarded-user'], terminal_response: true };
  const { writes } = await fixture(page, configured);
  await edit(page);
  await revealPolicy(page);
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_id').fill('acct:records');
  await page.locator('#route-field-resource_policy_enforce').uncheck();
  await expect(page.locator('#route-message')).toContainText('cannot use terminal external authorization responses');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});
