import { test, expect } from '@playwright/test';

const publicJwks = { keys: [{ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig', kid: 'fixture', x: 'A'.repeat(43) }] };
const verification = {
  issuer: 'https://issuer.example.test/', audiences: ['hangang-api'], profile: 'rfc9068', algorithms: ['EdDSA'],
  leeway_seconds: 0, max_lifetime_seconds: 3600, scope_claim: 'scope', groups_claim: 'groups',
  required_scopes: ['read'], required_groups: ['operators'],
};
const baseRoute = {
  id: 'jwt-route', access_mode: 'protected', host: 'api.example.test', path_prefix: '/secure',
  backends: ['http://127.0.0.1:8080'], auth: null, basic_auth: null,
  jwt_auth: { verification, keys: { source: 'local', jwks: publicJwks }, hide_credentials: true, identity_header: 'x-verified-user' },
  resource_policy: { resource_id: 'records', principal: { source: 'jwt' }, allow: [{ subjects: ['alice'], methods: ['GET'] }] },
};

async function fixture(page, initial = baseRoute, locale = 'en') {
  const routes = new Map([[initial.id, structuredClone(initial)]]);
  const writes = [];
  let revision = 7;
  let terminations;
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: routes.size, tcp_routes: 0, uptime_seconds: 1, metrics: { jwt_lease_terminations_total: terminations }, state: { ready: true } } });
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
  return { writes, routes, setTerminations(value) { terminations = value; } };
}

async function edit(page) {
  await page.locator('[data-route-id="jwt-route"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function reveal(page, name) {
  const section = page.locator(`#route-field-${name}`).locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

test('JWT route appears under auth policy and preserves local verification with a native edit', async ({ page }) => {
  const { writes } = await fixture(page);
  await page.locator('.route-policy-filter').selectOption('auth');
  await expect(page.locator('[data-route-id="jwt-route"]')).toBeVisible();
  await edit(page);
  await reveal(page, 'jwt_auth_enabled');
  await expect(page.locator('#route-field-jwt_auth_enabled')).toBeChecked();
  await expect(page.locator('#route-field-jwt_issuer')).toHaveValue('https://issuer.example.test/');
  await expect(page.locator('#route-field-jwt_required_scopes')).toHaveValue('read');
  await page.locator('#route-field-priority').fill('8');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].jwt_auth).toEqual(baseRoute.jwt_auth);
  expect(writes[0].resource_policy).toEqual(baseRoute.resource_policy);
});

test('advanced JWT JSON add and remote endpoint change survive an unrelated native edit', async ({ page }) => {
  const initial = structuredClone(baseRoute);
  initial.jwt_auth = null; initial.resource_policy = null;
  const { writes } = await fixture(page, initial);
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const draft = structuredClone(initial);
  draft.jwt_auth = { verification, keys: { source: 'remote', config: {
    endpoint: { kind: 'jwks', url: 'https://issuer.example.test/jwks' },
    cache_ttl_seconds: 90, refresh_cooldown_seconds: 5, timeout_ms: 800, ca_pem: null,
  } }, hide_credentials: false, identity_header: null };
  draft.resource_policy = structuredClone(baseRoute.resource_policy);
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-jwt_auth_enabled')).toBeChecked();
  await expect(page.locator('#route-field-jwt_key_source')).toHaveValue('remote');
  await expect(page.locator('#route-field-jwt_jwks_url')).toHaveValue('https://issuer.example.test/jwks');
  await page.locator('#route-field-priority').fill('2');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].jwt_auth).toEqual(draft.jwt_auth);
  expect(writes[0].resource_policy).toEqual(draft.resource_policy);
});

test('advanced JSON switches Basic to JWT and keeps additional external authorization', async ({ page }) => {
  const initial = structuredClone(baseRoute);
  initial.basic_auth = { realm: 'restricted', credentials: [`alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`], hide_credentials: true, identity_header: null };
  initial.jwt_auth = null;
  initial.resource_policy = null;
  const { writes } = await fixture(page, initial);
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const draft = structuredClone(initial);
  draft.basic_auth = null;
  draft.jwt_auth = structuredClone(baseRoute.jwt_auth);
  draft.auth = { url: 'http://auth.example.test/check', request_headers: ['x-request-id'], response_headers: [], timeout_ms: 800, forward_response: false };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-basic_auth_credentials')).toHaveValue('');
  await expect(page.locator('#route-field-auth_url')).toHaveValue('http://auth.example.test/check');
  await page.locator('#route-field-priority').fill('4');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].basic_auth).toBeNull();
  expect(writes[0].jwt_auth).toEqual(draft.jwt_auth);
  expect(writes[0].auth).toEqual(draft.auth);
});

test('native controls add signed-token auth without converting it into browser login', async ({ page }) => {
  const initial = structuredClone(baseRoute);
  initial.access_mode = 'public'; initial.jwt_auth = null; initial.resource_policy = null;
  const { writes } = await fixture(page, initial);
  await edit(page);
  await reveal(page, 'access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await reveal(page, 'jwt_auth_enabled');
  await page.locator('#route-field-jwt_auth_enabled').check();
  await page.locator('#route-field-jwt_issuer').fill('https://issuer.example.test/');
  await page.locator('#route-field-jwt_audiences').fill('hangang-api');
  await page.locator('#route-field-jwt_algorithms').fill('EdDSA');
  await page.locator('#route-field-jwt_local_jwks').fill(JSON.stringify(publicJwks));
  await page.locator('#route-field-jwt_required_scopes').fill('read');
  await page.locator('#route-field-jwt_required_groups').fill('operators');
  await page.locator('#route-field-jwt_identity_header').fill('x-verified-user');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].access_mode).toBe('protected');
  expect(writes[0].basic_auth).toBeNull();
  expect(writes[0].jwt_auth).toEqual(baseRoute.jwt_auth);
});

test('Basic and JWT cannot combine, while Protected cannot lose its only authenticator', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await reveal(page, 'basic_auth_credentials');
  await page.locator('#route-field-basic_auth_credentials').fill(`alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`);
  await expect(page.locator('#route-message')).toContainText('cannot share Authorization');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  await page.locator('#route-field-basic_auth_credentials').fill('');
  await reveal(page, 'jwt_auth_enabled');
  await page.locator('#route-field-jwt_auth_enabled').uncheck();
  await expect(page.locator('#route-message')).toContainText('Protected access requires Basic, JWT, workload mTLS or external authorization');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
});

test('Korean JWT controls and raw public JWKS remain readable', async ({ page }) => {
  await fixture(page, baseRoute, 'ko');
  await page.locator('[data-route-id="jwt-route"]').getByRole('button', { name: '편집' }).click();
  await reveal(page, 'jwt_auth_enabled');
  await expect(page.locator('label[for="route-field-jwt_auth_enabled"]')).toContainText('JWT 인증 사용');
  await expect(page.locator('label[for="route-field-jwt_issuer"]')).toContainText('발급자');
  await expect(page.locator('#route-field-jwt_local_jwks')).toHaveValue(/"kid": "fixture"/);
});

test('native revocation controls preserve exact token IDs and allow an explicit clear', async ({ page }) => {
  const initial = structuredClone(baseRoute);
  initial.jwt_auth.verification.revocation = { issued_before: 1700000000, token_ids: ['first-id', 'id with space'] };
  const { writes } = await fixture(page, initial);
  await edit(page);
  await reveal(page, 'jwt_issued_before');
  await expect(page.locator('#route-field-jwt_issued_before')).toHaveValue('1700000000');
  await expect(page.locator('#route-field-jwt_token_ids')).toHaveValue('first-id\nid with space');
  await page.locator('#route-field-priority').fill('9');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].jwt_auth.verification.revocation).toEqual(initial.jwt_auth.verification.revocation);

  await edit(page);
  await reveal(page, 'jwt_issued_before');
  await page.locator('#route-field-jwt_issued_before').fill('');
  await page.locator('#route-field-jwt_token_ids').fill('');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[1].jwt_auth.verification).not.toHaveProperty('revocation');
  expect(writes[1].jwt_auth.keys).toEqual(initial.jwt_auth.keys);
});

test('advanced JWT revocation JSON survives an unrelated native edit', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const draft = structuredClone(baseRoute);
  draft.jwt_auth.verification.revocation = { issued_before: 253402300799, token_ids: ['exact-α', 'exact-id'] };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-jwt_issued_before')).toHaveValue('253402300799');
  await expect(page.locator('#route-field-jwt_token_ids')).toHaveValue('exact-α\nexact-id');
  await page.locator('#route-field-priority').fill('4');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].jwt_auth).toEqual(draft.jwt_auth);
});

test('invalid duplicate, whitespace and out-of-range JWT revocation inputs do not publish', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page);
  await reveal(page, 'jwt_token_ids');
  await page.locator('#route-field-jwt_token_ids').fill('same-id\nsame-id');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('at most 1,024 distinct exact values');
  expect(writes).toHaveLength(0);
  await page.locator('#route-field-jwt_token_ids').fill(' leading-space');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('without surrounding whitespace');
  expect(writes).toHaveLength(0);
  await page.locator('#route-field-jwt_token_ids').fill('valid-id');
  await page.locator('#route-field-jwt_issued_before').fill('253402300800');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText('Reject tokens issued before');
  expect(writes).toHaveLength(0);
});

test('Korean revocation controls explain publication and exact jti values', async ({ page }) => {
  await fixture(page, baseRoute, 'ko');
  await page.locator('[data-route-id="jwt-route"]').getByRole('button', { name: '편집' }).click();
  await reveal(page, 'jwt_issued_before');
  await expect(page.locator('label[for="route-field-jwt_issued_before"]')).toContainText('이 시각 이전 발급 토큰 거부');
  await expect(page.locator('label[for="route-field-jwt_token_ids"]')).toContainText('거부할 토큰 ID');
  await expect(page.locator('#route-field-jwt_token_ids-help')).toContainText('Bearer 토큰을 입력하지 마세요');
});

for (const locale of ['en', 'ko']) {
  test(`JWT lease counter exposes unavailable and refreshed evidence in ${locale}`, async ({ page }) => {
    const control = await fixture(page, baseRoute, locale);
    await page.locator('[data-view="status"]').click();
    const label = locale === 'ko' ? 'JWT 스트림 종료' : 'JWT stream terminations';
    const card = page.locator('.metric').filter({ has: page.getByText(label, { exact: true }) });
    await expect(card.locator('.metric-value')).toHaveText('—');
    control.setTerminations(3);
    await page.locator('#refresh-status').click();
    await expect(card.locator('.metric-value')).toHaveText('3');
    await expect(card).toHaveClass(/is-error/);
  });
}
