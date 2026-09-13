import { test, expect } from '@playwright/test';

const http = { id: 'country-http', host: 'example.test', path_prefix: '/', backends: ['http://127.0.0.1:8080'] };
const tcp = { id: 'country-tcp', listen: '127.0.0.1:9001', backends: ['127.0.0.1:9002'] };
const source = { file: '/var/lib/hangang/country.mmdb', max_file_bytes: 33554432, max_age_days: 14, reload_interval_seconds: 30 };

async function fixture(page, { locale = 'en', initialSource = source } = {}) {
  const routes = { http: new Map([[http.id, structuredClone(http)]]), tcp: new Map([[tcp.id, structuredClone(tcp)]]) };
  const routeWrites = { http: [], tcp: [] }; const configWrites = [];
  let revision = 7;
  let config = { revision, http: [...routes.http.values()], tcp: [...routes.tcp.values()], certificates: [], ...(initialSource ? { geoip_database: structuredClone(initialSource) } : {}) };
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: routes.http.size, tcp_routes: routes.tcp.size, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') { config = request.postDataJSON(); configWrites.push(structuredClone(config)); revision++; config.revision = revision; }
      return handled.fulfill({ json: config, headers: { etag: `"${revision}"` } });
    }
    for (const kind of ['http', 'tcp']) {
      if (path === `/v1/routes/${kind}`) return handled.fulfill({ json: { revision, routes: [...routes[kind].values()] }, headers: { etag: `"${revision}"` } });
      if (path.startsWith(`/v1/routes/${kind}/`)) {
        const id = decodeURIComponent(path.slice(`/v1/routes/${kind}/`.length));
        if (request.method() === 'PUT') { const value = request.postDataJSON(); routeWrites[kind].push(value); routes[kind].set(id, value); revision++; return handled.fulfill({ json: { revision }, headers: { etag: `"${revision}"` } }); }
        return handled.fulfill({ json: routes[kind].get(id), headers: { etag: `"${revision}"` } });
      }
    }
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { routeWrites, configWrites };
}

async function edit(page, kind) {
  await page.locator(`[data-view="${kind}"]`).click();
  await page.locator(`[data-route-id="country-${kind}"] td:last-child button`).first().click();
  await expect(page.locator('#route-dialog')).toBeVisible();
  const section = page.locator('#route-field-country_policy_action').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

async function save(page) {
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
}

test('HTTP native country policy configures, disables and removes with exact wire values', async ({ page }) => {
  const { routeWrites } = await fixture(page);
  await edit(page, 'http');
  await page.locator('#route-field-country_policy_action').selectOption('configured');
  await page.locator('#route-field-country_policy_allow').fill('KR\nUS');
  await page.locator('#route-field-country_policy_deny').fill('US');
  await expect(page.locator('#route-dialog')).toContainText('not identity or a live location guarantee');
  await save(page);
  expect(routeWrites.http[0].country_policy).toEqual({ allow: ['KR', 'US'], deny: ['US'], on_unknown: 'deny' });

  await edit(page, 'http');
  await expect(page.locator('#route-field-country_policy_allow')).toHaveValue('KR\nUS');
  await page.locator('#route-field-country_policy_enforce').uncheck();
  await save(page);
  expect(routeWrites.http[1].country_policy).toEqual({ ...routeWrites.http[0].country_policy, enforce: false });

  await edit(page, 'http');
  await page.locator('#route-field-country_policy_action').selectOption('remove');
  await save(page);
  expect(routeWrites.http[2]).not.toHaveProperty('country_policy');
});

test('TCP Korean native policy and advanced JSON synchronize without losing unrelated route fields', async ({ page }) => {
  const { routeWrites } = await fixture(page, { locale: 'ko' });
  await edit(page, 'tcp');
  await page.locator('.advanced-editor summary').click();
  const draft = { ...tcp, country_policy: { allow: [], deny: ['RU'], on_unknown: 'allow', enforce: false } };
  await page.locator('#route-json').fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-country_policy_action')).toHaveValue('configured');
  await expect(page.locator('#route-field-country_policy_deny')).toHaveValue('RU');
  await expect(page.locator('label[for="route-field-country_policy_on_unknown"]')).toHaveText('국가를 알 수 없을 때');
  await page.locator('#route-field-priority').fill('5');
  await save(page);
  expect(routeWrites.tcp[0].country_policy).toEqual(draft.country_policy);
  expect(routeWrites.tcp[0].priority).toBe(5);
});

test('invalid country lists and malformed advanced JSON never write or silently erase draft', async ({ page }) => {
  const { routeWrites } = await fixture(page);
  await edit(page, 'http');
  await page.locator('#route-field-country_policy_action').selectOption('configured');
  await expect(page.locator('#route-message')).toContainText('1–256');
  await page.locator('#route-field-country_policy_allow').fill('kr');
  await expect(page.locator('#route-message')).toContainText('two uppercase');
  await page.locator('#route-field-country_policy_allow').fill('KR\nKR');
  await expect(page.locator('#route-message')).toContainText('unique');
  await page.locator('#route-field-country_policy_allow').fill('KR');
  await page.locator('#route-field-country_policy_on_unknown').selectOption('allow');
  await expect(page.locator('#route-message')).toContainText('cannot be allowed');
  await page.locator('#save-route').click(); expect(routeWrites.http).toHaveLength(0);

  await page.locator('.advanced-editor summary').click();
  const malformed = { ...http, country_policy: { allow: null, deny: ['RU'], on_unknown: 'deny' } };
  await page.locator('#route-json').fill(JSON.stringify(malformed));
  await page.locator('#route-field-priority').fill('2');
  await expect(page.locator('#route-message')).toContainText('must contain country codes');
  await page.locator('#save-route').click(); expect(routeWrites.http).toHaveLength(0);
  expect(JSON.parse(await page.locator('#route-json').inputValue()).country_policy.allow).toBeNull();
});

test('GeoIP source controls stage bounded node-local path, survive JSON edits and remove explicitly', async ({ page }) => {
  const { configWrites } = await fixture(page, { initialSource: null });
  await page.locator('[data-view="config"]').click();
  const panel = page.locator('#geoip-section'); await panel.locator('summary').click();
  await page.locator('#geoip-action').selectOption('configured');
  await expect(page.locator('#geoip-message')).toContainText('absolute normalized path');
  await page.locator('#geoip-file').fill('/var/lib/hangang/country.mmdb');
  await page.locator('#geoip-max_file_bytes').fill('67108864');
  await page.locator('#geoip-max_age_days').fill('90');
  await page.locator('#geoip-reload_interval_seconds').fill('3600');
  await expect(page.locator('#geoip-message')).toBeEmpty();
  await expect(page.locator('#config-editor')).toHaveValue(/"geoip_database"/);
  await page.locator('#apply-config').click();
  expect(configWrites[0].geoip_database).toEqual({ file: '/var/lib/hangang/country.mmdb', max_file_bytes: 67108864, max_age_days: 90, reload_interval_seconds: 3600 });

  const draft = { ...configWrites[0], geoip_database: { ...source, max_age_days: 25 } };
  await page.locator('#config-editor').fill(JSON.stringify(draft));
  await expect(page.locator('#geoip-max_age_days')).toHaveValue('25');
  await page.locator('#geoip-action').selectOption('remove');
  await expect(page.locator('#config-editor')).not.toHaveValue(/"geoip_database"/);
  await page.locator('#apply-config').click();
  expect(configWrites[1]).not.toHaveProperty('geoip_database');
});

test('malformed GeoIP source remains in advanced JSON and blocks native removal by accident', async ({ page }) => {
  const { configWrites } = await fixture(page);
  await page.locator('[data-view="config"]').click();
  const panel = page.locator('#geoip-section'); await panel.locator('summary').click();
  const draft = { revision: 7, http: [http], tcp: [tcp], certificates: [], geoip_database: ['invalid'] };
  await page.locator('#config-editor').fill(JSON.stringify(draft));
  await page.locator('#geoip-action').selectOption('remove');
  await expect(page.locator('#geoip-message')).toContainText('object or null');
  await page.locator('#apply-config').click();
  expect(configWrites).toHaveLength(0);
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).geoip_database).toEqual(['invalid']);
});

test('logout removes node-local GeoIP file metadata from configuration controls', async ({ page }) => {
  await fixture(page);
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#geoip-file')).toHaveValue('/var/lib/hangang/country.mmdb');
  await page.locator('#logout-button').click();
  await expect(page.locator('#geoip-file')).toHaveValue('');
  await expect(page.locator('#config-editor')).toHaveValue('');
});
