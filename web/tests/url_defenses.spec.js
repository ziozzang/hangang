import { test, expect } from '@playwright/test';

async function open(page, settings = {}, security = null) {
  const writes = [];
  let document = { revision: 7, http: [], tcp: [], settings };
  await page.route('**/*', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (path === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true }, settings: { path_blocks_count: 2, path_rate_limits_count: 1, path_failure_bans_count: 1, failure_ban_scope: 'url', security_state_backend: 'local' } } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: '' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') { writes.push(request.postDataJSON()); document = { ...request.postDataJSON(), revision: 8 }; }
      return route.fulfill({ json: document, headers: { etag: `"${document.revision}"` } });
    }
    if (path.startsWith('/v1/security/') && security) return security(route);
    if (path === '/v1/config/validate') return route.fulfill({ json: { valid: true, revision: 7 } });
    return route.fulfill({ status: 404, body: '' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await expect(page.locator('#setting-active-path_blocks')).toHaveText('2 configured rules');
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#settings-form')).toBeVisible();
  return writes;
}

test('URL defenses stage, preserve other settings, publish and clear with scope and locale', async ({ page }) => {
  const writes = await open(page, { http_recording: { default_action: 'drop', rules: [] }, health_path: '/healthz', path_blocks: [{ path: '/.git' }] });
  await expect(page.getByLabel('Blocked URL namespaces')).toHaveValue(/\.git/);
  const blocks = [{ path: '/.git' }, { path: '/private', hosts: ['*.example.test', '[::1]'] }];
  const rates = [{ path: '/login', tps: 5, burst: 10, limits: [{ requests: 100, window_seconds: 60 }, { requests: 1000, window_seconds: 86400 }] }, { path: '/signup', limits: [{ requests: 20, window_seconds: 60 }] }];
  const bans = [{ path: '/login', failures: 5, window_seconds: 60, ban_seconds: 300 }];
  await page.getByLabel('Blocked URL namespaces').fill(JSON.stringify(blocks));
  await page.getByLabel('URL request rate limits').fill(JSON.stringify(rates));
  await page.getByLabel('URL failure bans').fill(JSON.stringify(bans));
  await page.getByLabel('Failure ban scope').selectOption('global');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.getByLabel('실패 누적 차단 범위')).toHaveValue('global');
  await expect(page.getByLabel('URL 요청 속도 제한')).toHaveValue(JSON.stringify(rates));
  await page.locator('#apply-config').click();
  await expect.poll(() => writes.length).toBe(1);
  await expect(page.locator('#config-message')).toContainText('8');
  await expect(page.locator('#apply-config')).toBeEnabled();
  expect(writes[0].settings).toEqual({ http_recording: { default_action: 'drop', rules: [] }, health_path: '/healthz', path_blocks: blocks, path_rate_limits: rates, path_failure_bans: bans, failure_ban_scope: 'global' });
  for (const key of ['path_blocks', 'path_rate_limits', 'path_failure_bans']) await page.locator(`#setting-${key}`).fill('');
  await page.locator('#setting-failure_ban_scope').selectOption('');
  const staged = JSON.parse(await page.locator('#config-editor').inputValue());
  expect(staged.settings).toEqual({ http_recording: { default_action: 'drop', rules: [] }, health_path: '/healthz' });
  await page.locator('#logout-button').click();
  await expect(page.locator('#setting-path_blocks')).toHaveValue('');
});

for (const [key, draft] of [
  ['path_blocks', [{ path: '/a/../secret' }]], ['path_blocks', [{ path: '/a%2fb' }]],
  ['path_blocks', [{ path: '/.git' }, { path: '/.git', hosts: [] }]],
  ['path_blocks', [{ path: '/a', hosts: ['bad host'] }]],
  ['path_rate_limits', [{ path: '/login', tps: 0 }]],
  ['path_rate_limits', [{ path: '/login' }]],
  ['path_rate_limits', [{ path: '/login', limits: [{ requests: 2, window_seconds: 86401 }] }]],
  ['path_rate_limits', [{ path: '/login', tps: 1, burst: 1000001 }]],
  ['path_failure_bans', [{ path: '/login', failures: 1, window_seconds: 1, ban_seconds: 1, statuses: [200] }]],
  ['path_failure_bans', [{ path: '/login', failures: 1, window_seconds: 1, ban_seconds: 1, include_subpaths: 'false' }]],
]) test(`invalid ${key} draft blocks publication: ${JSON.stringify(draft)}`, async ({ page }) => {
  const writes = await open(page);
  await page.locator(`#setting-${key}`).fill(JSON.stringify(draft));
  await expect(page.locator(`#setting-${key}`)).toHaveAttribute('aria-invalid', 'true');
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('Fleet settings');
  expect(writes).toHaveLength(0);
});


test('IP ban menu queries safely and releases exactly one confirmed IP', async ({ page }) => {
  const calls = []; const hostile = '<img src=x onerror="window.__banInjected=1">';
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, {}, async route => {
    const request = route.request(); calls.push({ method: request.method(), url: request.url(), body: request.postData() ? request.postDataJSON() : null });
    if (request.method() === 'POST') return route.fulfill({ json: { released: 1 } });
    return route.fulfill({ json: { scope: 'host', distributed: true, truncated: true, bans: [{ ip: '192.0.2.10', path: hostile, remaining_seconds: 120 }] } });
  });
  await page.locator('[data-view="security"]').click();
  await expect(page.locator('#security-ban-rows')).toContainText(hostile);
  await expect(page.locator('#security-ban-meta')).toContainText('Shared Redis');
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  expect(await page.evaluate(() => window.__banInjected)).toBeUndefined();
  await expect(page.locator('#security-ban-message')).toContainText('List truncated');
  await page.getByLabel('Search banned IP').fill('192.0.2.10');
  await page.locator('#security-ban-search-form').getByRole('button', { name: 'Search', exact: true }).click();
  await expect.poll(() => calls.filter(call => call.url.endsWith('?ip=192.0.2.10')).length).toBe(1);
  await page.getByLabel('IP to release').fill('192.0.2.10');
  await page.getByRole('button', { name: 'Release IP', exact: true }).click();
  await expect(page.locator('#confirm-dialog')).toContainText('192.0.2.10');
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(0);
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#security-ban-message')).toContainText('Release completed');
  expect(calls.filter(call => call.method === 'POST').map(call => call.body)).toEqual([{ ip: '192.0.2.10' }]);
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.getByLabel('해제할 IP')).toHaveValue('192.0.2.10');
  await expect(page.locator('#security-ban-rows')).toContainText('120초 남음');
});

test('late privileged IP ban response cannot repaint after logout or a locale change', async ({ page }) => {
  let release; let requested = false;
  const gate = new Promise(resolve => { release = resolve; });
  await open(page, {}, async route => {
    requested = true; await gate;
    return route.fulfill({ json: { scope: 'url', distributed: false, truncated: false, bans: [{ ip: '192.0.2.10', path: '/login', remaining_seconds: 30 }] } });
  });
  await page.locator('[data-view="security"]').click();
  await expect.poll(() => requested).toBe(true);
  await page.locator('#logout-button').click(); release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await page.locator('#locale-select-login').selectOption('ko');
  await expect(page.locator('#security-ban-rows')).toBeEmpty();
  await expect(page.locator('#security-ban-meta')).toBeEmpty();
  await expect(page.locator('#security-ban-release-ip')).toHaveValue('');
});


test('shared security Redis stages only environment references and rejects inline secrets', async ({ page }) => {
  const writes = await open(page, { health_path: '/healthz' });
  await page.getByLabel('Shared security Redis').fill(JSON.stringify({ url_env: 'HANGANG_SECURITY_REDIS_URL', namespace: 'hangang-security' }));
  let settings = JSON.parse(await page.locator('#config-editor').inputValue()).settings;
  expect(settings.security_redis).toEqual({ url_env: 'HANGANG_SECURITY_REDIS_URL', namespace: 'hangang-security' });
  await page.getByLabel('Shared security Redis').fill(JSON.stringify({ url: 'redis://localhost:6379', namespace: 'hangang-security' }));
  await expect(page.locator('#setting-security_redis')).toHaveAttribute('aria-invalid', 'true');
  await page.locator('#apply-config').click();
  expect(writes).toHaveLength(0);
  await page.locator('#setting-security_redis').fill('');
  settings = JSON.parse(await page.locator('#config-editor').inputValue()).settings;
  expect(settings).toEqual({ health_path: '/healthz' });
});


test('private plaintext Redis flag round-trips only when explicitly chosen', async ({ page }) => {
  const writes = await open(page, { health_path: '/healthz' });
  const base = { url_env: 'HANGANG_SECURITY_REDIS_URL', namespace: 'hangang-security' };
  await page.locator('#setting-security_redis').fill(JSON.stringify(base));
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).settings.security_redis).toEqual(base);
  await page.locator('#setting-security_redis').fill(JSON.stringify({ ...base, allow_insecure_remote: 'true' }));
  await expect(page.locator('#setting-security_redis')).toHaveAttribute('aria-invalid', 'true');
  await page.locator('#apply-config').click();
  expect(writes).toHaveLength(0);
  const explicit = { ...base, allow_insecure_remote: true };
  await page.locator('#setting-security_redis').fill(JSON.stringify(explicit));
  await page.locator('#apply-config').click();
  await expect(page.locator('#config-message')).toContainText('8');
  expect(writes[0].settings.security_redis).toEqual(explicit);
  await page.locator('#setting-security_redis').fill(JSON.stringify({ ...base, allow_insecure_remote: false }));
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).settings.security_redis.allow_insecure_remote).toBe(false);
});


test('URL allowlists preserve other settings, validate CIDRs and GeoIP dependency, and publish', async ({ page }) => {
  const writes = await open(page, { health_path: '/healthz', security_redis: { url_env: 'HANGANG_SECURITY_REDIS_URL', namespace: 'hangang-security' } });
  const control = page.getByLabel('URL country and IP allowlists');
  await control.fill(JSON.stringify([{ path: '/login', allow_cidrs: ['192.0.2.0/33'] }]));
  await expect(control).toHaveAttribute('aria-invalid', 'true');
  await control.fill(JSON.stringify([{ path: '/login', allow_countries: ['KR'] }]));
  await expect(page.locator('#settings-message')).toContainText('GeoIP');
  await page.locator('#apply-config').click(); expect(writes).toHaveLength(0);
  const rules = [{ path: '/login', hosts: ['app.example.test'], allow_cidrs: ['192.0.2.0/24', '2001:db8::/32'] }];
  await control.fill(JSON.stringify(rules));
  await page.locator('#apply-config').click(); await expect(page.locator('#config-message')).toContainText('8');
  expect(writes[0].settings.path_allowlists).toEqual(rules);
  expect(writes[0].settings.security_redis).toEqual({ url_env: 'HANGANG_SECURITY_REDIS_URL', namespace: 'hangang-security' });
  await control.fill(''); expect(JSON.parse(await page.locator('#config-editor').inputValue()).settings.path_allowlists).toBeUndefined();
});


test('authenticated country controls retain DB-IP attribution in both locales', async ({ page }) => {
  await open(page);
  const link = page.locator('#geoip-attribution').getByRole('link');
  await expect(link).toBeVisible();
  await expect(link).toHaveText('IP Geolocation by DB-IP');
  await expect(link).toHaveAttribute('href', 'https://db-ip.com');
  await expect(link).toHaveAttribute('target', '_blank');
  await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  await page.locator('#locale-select').selectOption('ko');
  await expect(link).toHaveText('GeoIP 데이터: DB-IP');
  await expect(page.getByLabel('URL 국가·IP 허용 목록')).toBeVisible();
});


test('URL CSRF origin policy validates and round-trips alongside existing settings', async ({ page }) => {
  const writes = await open(page, { health_path: '/healthz' });
  const control = page.getByLabel('URL CSRF origin policy');
  for (const rule of [
    { path: '/login', allow_origins: ['https://portal.internal/path'] },
    { path: '/login', allow_origins: ['https://portal.internal', 'https://PORTAL.internal:443/'] },
    { path: '/login', allow_same_origin: false },
    { path: '/login', methods: ['CONNECT'] },
  ]) {
    await control.fill(JSON.stringify([rule])); await expect(control).toHaveAttribute('aria-invalid', 'true');
    await page.locator('#apply-config').click(); expect(writes).toHaveLength(0);
  }
  const rules = [{ path: '/login', hosts: ['app.example.test'], allow_origins: ['https://portal.internal.example.test'], allow_same_origin: true, allow_missing_origin: false, methods: ['POST', 'PUT'] }];
  await control.fill(JSON.stringify(rules));
  await page.locator('#locale-select').selectOption('ko'); await expect(page.getByLabel('URL CSRF 출처 정책')).toHaveValue(JSON.stringify(rules));
  await page.locator('#apply-config').click(); await expect(page.locator('#config-message')).toContainText('8');
  expect(writes[0].settings).toEqual({ health_path: '/healthz', path_csrf: rules });
  await page.locator('#setting-path_csrf').fill(''); expect(JSON.parse(await page.locator('#config-editor').inputValue()).settings).toEqual({ health_path: '/healthz' });
  await page.locator('[data-view="certificates"]').click();
  await expect(page.locator('#view-certificates')).toContainText('Certificate Transparency');
  await expect(page.locator('#view-certificates')).toContainText('www 별칭');
  await expect(page.locator('#view-certificates')).toContainText('DNS-01');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#view-certificates')).toContainText('A base domain, its www alias, and its matching wildcard share one management group');
});
