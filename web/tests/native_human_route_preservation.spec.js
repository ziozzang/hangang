import { test, expect } from '@playwright/test';

// Browser serialization only: these future route fields do not prove runtime support.
const original = {
  id: 'human-route', host: 'human.example.test', path_prefix: '/',
  backends: ['http://127.0.0.1:8080'], headers: {}, json: {}, deny_cidrs: [],
  auth: {
    url: 'https://auth.example.test/verify', request_headers: ['cookie'],
    response_headers: ['x-forwarded-user'], timeout_ms: 1000, forward_response: true,
    native_resource: {
      issuer_ref: 'hopae-human', audience: 'orders-api', key_epoch: 1,
      public_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      maximum_body_bytes: 16384, body_timeout_ms: 900, project_credentials: true,
      observed: {
        authentication_class: 'human', identity_authority: 'hopae-human',
        minimum_profile_revision: 7, minimum_application_generation: 3,
        minimum_key_registry_revision: 1, source_error_ppm: 0,
        receiver_error_ppm: 0, maximum_final_header_bytes: 8192,
      },
      human_binding: { app_id: 'orders', header_policy_revision: 11, header_names: ['x-tenant'] },
    },
  },
};

async function fixture(page, routeDocument = original) {
  const writes = [];
  await page.route('**/*', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return route.fulfill({ json: {
      revision: 3, http_routes: 1, tcp_routes: 0, uptime_seconds: 10,
      metrics: { requests_total: 0, errors_total: 0, active_connections: 1 },
      state: { ready: true },
    } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return route.fulfill({ json: { records: [], retention_seconds: 60 } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: 'stream unavailable' });
    if (path === '/v1/routes/http/human-route' && request.method() === 'PUT') {
      writes.push({ document: request.postDataJSON(), ifMatch: request.headers()['if-match'] });
      return route.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/http/human-route') return route.fulfill({ json: routeDocument, headers: { etag: '"3"' } });
    if (path === '/v1/routes/http') return route.fulfill({ json: { revision: 3, routes: [routeDocument] }, headers: { etag: '"3"' } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 3, http: [routeDocument], tcp: [] } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  return writes;
}

async function openEditor(page) {
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

test('native Human configuration survives ordinary route form edit and CAS save', async ({ page }) => {
  const writes = await fixture(page);
  await openEditor(page);
  await page.locator('#route-field-priority').fill('9');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].ifMatch).toBe('"3"');
  expect(writes[0].document.priority).toBe(9);
  expect(writes[0].document.auth.native_resource).toEqual(original.auth.native_resource);
});

test('advanced Human scope edits survive form synchronization without aliasing the original', async ({ page }) => {
  const writes = await fixture(page);
  await openEditor(page);
  await page.locator('#route-dialog .advanced-editor:has(> #route-json) > summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.auth.native_resource.human_binding.header_policy_revision = 12;
  draft.auth.native_resource.human_binding.header_names = ['x-tenant', 'x-project'];
  draft.auth.native_resource.observed.minimum_profile_revision = 8;
  await json.fill(JSON.stringify(draft, null, 2));
  await page.locator('#route-field-priority').fill('7');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].ifMatch).toBe('"3"');
  expect(writes[0].document.auth.native_resource).toEqual(draft.auth.native_resource);
  expect(original.auth.native_resource.human_binding.header_policy_revision).toBe(11);
});
