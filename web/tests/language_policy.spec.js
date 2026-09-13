import { test, expect } from '@playwright/test';

const baseRoute = { id: 'language', host: 'example.test', path_prefix: '/', backends: ['http://127.0.0.1:8080'] };

async function fixture(page, initial = baseRoute, locale = 'en') {
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
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision, routes: [...routes.values()] }, headers: { etag: `"${revision}"` } });
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

async function edit(page) {
  await page.locator('[data-route-id="language"] td:last-child button').first().click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function reveal(page) {
  const section = page.locator('#route-field-language_policy_action').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

async function save(page) {
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
}

test('English controls configure, disable and remove a language policy through route PUT', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page); await reveal(page);
  await page.locator('#route-field-language_policy_action').selectOption('configured');
  await page.locator('#route-field-language_policy_mode').selectOption('preferred');
  await page.locator('#route-field-language_policy_on_missing').selectOption('deny');
  await page.locator('#route-field-language_policy_allow').fill('ko\nen');
  await page.locator('#route-field-language_policy_deny').fill('fr');
  await expect(page.locator('#route-dialog')).toContainText('q=0');
  await expect(page.locator('#route-dialog')).toContainText('not identity, country or location');
  await save(page);
  expect(writes[0].language_policy).toEqual({ mode: 'preferred', allow: ['ko', 'en'], deny: ['fr'], on_missing: 'deny' });

  await edit(page);
  await expect(page.locator('#route-field-language_policy_allow')).toHaveValue('ko\nen');
  await page.locator('#route-field-language_policy_enforce').uncheck();
  await save(page);
  expect(writes[1].language_policy).toEqual({ ...writes[0].language_policy, enforce: false });

  await edit(page);
  await page.locator('#route-field-language_policy_action').selectOption('remove');
  await save(page);
  expect(writes[2]).not.toHaveProperty('language_policy');
});

test('Korean controls and advanced JSON round-trip with an unrelated native edit', async ({ page }) => {
  const { writes } = await fixture(page, baseRoute, 'ko');
  await edit(page);
  await page.locator('.advanced-editor summary').click();
  const draft = { ...baseRoute, language_policy: { mode: 'any', allow: ['ko', '*'], deny: ['fr-CA'], on_missing: 'allow', enforce: false } };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-language_policy_action')).toHaveValue('configured');
  await expect(page.locator('#route-field-language_policy_allow')).toHaveValue('ko\n*');
  await expect(page.locator('label[for="route-field-language_policy_mode"]')).toHaveText('선호 언어 판정 방식');
  await expect(page.locator('#route-dialog')).toContainText('q=0');
  await page.locator('#route-field-priority').fill('3');
  await save(page);
  expect(writes[0].language_policy).toEqual(draft.language_policy);
});

test('invalid native and advanced policies do not produce writes or erase the draft', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page); await reveal(page);
  await page.locator('#route-field-language_policy_action').selectOption('configured');
  await expect(page.locator('#route-message')).toContainText('1–32');
  await page.locator('#route-field-language_policy_allow').fill('ko\nKO');
  await expect(page.locator('#route-message')).toContainText('unique within each list');
  await page.locator('#route-field-language_policy_allow').fill('ko-*');
  await expect(page.locator('#route-message')).toContainText('basic tags');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  await page.locator('.advanced-editor summary').click();
  const malformed = { ...baseRoute, language_policy: { mode: 'any', allow: ['ko', 'KO'], deny: [], on_missing: 'deny' } };
  await page.locator('#route-json').fill(JSON.stringify(malformed));
  await page.locator('#route-field-priority').fill('2');
  await expect(page.locator('#route-message')).toContainText('unique within each list');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  expect(JSON.parse(await page.locator('#route-json').inputValue()).language_policy.allow).toEqual(['ko', 'KO']);
});


test('advanced null language lists are not silently converted during native edits', async ({ page }) => {
  const { writes } = await fixture(page);
  await edit(page); await page.locator('.advanced-editor summary').click();
  const malformed = { ...baseRoute, language_policy: { mode: 'any', allow: null, deny: ['fr'], on_missing: 'deny' } };
  await page.locator('#route-json').fill(JSON.stringify(malformed));
  await page.locator('#route-field-priority').fill('2');
  await expect(page.locator('#route-message')).toContainText('must contain basic language ranges');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  expect(JSON.parse(await page.locator('#route-json').inputValue()).language_policy.allow).toBeNull();
});
