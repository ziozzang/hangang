import { test, expect } from '@playwright/test';

async function openSection(page, title) {
  const details = page.locator('details.form-section', { has: page.locator('summary .section-title', { hasText: new RegExp(`^${title}$`) }) });
  if (!(await details.evaluate((el) => el.open))) await details.locator('summary').click();
  await expect(details).toHaveJSProperty('open', true);
}

const base = process.env.HANGANG_ACTUAL_BASE;
const token = process.env.HANGANG_ACTUAL_TOKEN;

test.describe('actual embedded Hangang server', () => {
  test.skip(!base || !token, 'Set HANGANG_ACTUAL_BASE and HANGANG_ACTUAL_TOKEN to run the live smoke test.');

  test('serves CSP-protected assets and performs cache and route lifecycles', async ({ page, request }) => {
    const response = await request.get(`${base}/ui/`);
    expect(response.ok()).toBeTruthy();
    expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
    expect(response.headers()['content-security-policy']).toContain("style-src 'self'");

    await page.goto(`${base}/ui/`);
    if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
      await page.getByRole('button', { name: 'Use administrator token' }).click();
    }
    await page.getByLabel('Administrator token').fill(token);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#connection-state')).toHaveText('Connected');

    const cachePolicy = {
      memory: { max_bytes: 1048576, max_entries: 64, eviction: 'lru' },
      disk: null,
      max_object_bytes: 262144,
      max_fills: 4,
      fill_timeout_ms: 1000,
    };
    await page.getByRole('link', { name: 'Cache', exact: true }).click();
    await page.getByLabel('Global cache policy JSON').fill(JSON.stringify(cachePolicy));
    await page.getByRole('button', { name: 'Apply cache policy' }).click();
    await expect(page.locator('#cache-message')).toContainText('Cache policy is active');
    await expect(page.locator('#cache-state')).toHaveText('Enabled');

    const authorization = { Authorization: `Bearer ${token}` };
    const enabledCacheResponse = await request.get(`${base}/v1/cache`, { headers: authorization });
    expect(enabledCacheResponse.ok()).toBeTruthy();
    const enabledCache = await enabledCacheResponse.json();
    expect(enabledCache.enabled).toBe(true);
    // The server adds the invalidation generation (0 until a purge or an edit raises it).
    expect(enabledCache.config).toEqual({ ...cachePolicy, generation: 0 });
    expect(enabledCache.generation).toBe(0);
    expect(enabledCache.stats).toMatchObject({ memory_bytes: 0, memory_entries: 0 });
    // Fleet diagnostics: an instance id is always present; file mode has no store block.
    const liveStatus = await (await request.get(`${base}/v1/status`, { headers: authorization })).json();
    expect(liveStatus.instance.id).toMatch(/^[0-9a-f]{16}$/);
    expect(liveStatus.store).toBeNull();
    await expect(page.locator('#store-panel')).toBeHidden();

    await page.getByRole('button', { name: 'Purge cache' }).click();
    await page.getByRole('dialog', { name: 'Purge the cache?' }).getByRole('button', { name: 'Purge', exact: true }).click();
    await expect(page.getByText('Cache purged.')).toBeVisible();

    const credential = `alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`;
    await page.getByRole('link', { name: 'HTTP routes' }).click();
    await page.locator('#view-http > .page-head').getByRole('button', { name: 'New HTTP route' }).click();
    await page.getByLabel('Route ID').fill('ui-live-smoke');
    await page.getByLabel('Backends').fill('http://127.0.0.1:65534\nhttp://127.0.0.1:65533');
    await page.getByLabel('Require TLS').check();
    await page.getByLabel('Retries').fill('2');
    await page.getByLabel('Upstream timeout (ms)').fill('120000');
    await page.getByLabel('Path match mode').selectOption('segment_prefix');
    await openSection(page, 'Load balancing');
    await page.getByLabel('Balancing mode').selectOption('least_connections');
    await page.getByLabel('Backend weights').fill('3, 1');
    await page.getByLabel('Failure threshold').fill('3');
    await page.getByLabel('Cooldown (ms)').fill('15000');
    await openSection(page, 'External authorization');
    await page.getByLabel('Authorization URL').fill('https://auth.internal/check');
    await page.getByLabel('Identity response headers').fill('x-user');
    await page.getByLabel('Forward denial responses').check();
    await openSection(page, 'Basic authentication');
    await page.getByLabel('Credentials', { exact: true }).fill(credential);
    await page.getByLabel('Realm').fill('ops');
    await page.locator('input[name="basic_auth_identity_header"]').fill('x-authenticated-user');
    await page.getByLabel('Hide credentials from the upstream').check();
    await openSection(page, 'Response headers');
    await page.getByLabel('Set response headers').fill('x-frame-options: DENY');
    await page.getByLabel('Remove response headers').fill('server');
    await openSection(page, 'Cache');
    await page.locator('input[name="cache_ttl_seconds"]').fill('30');
    await page.locator('input[name="cache_max_ttl_seconds"]').fill('60');
    await page.getByRole('button', { name: 'Create route' }).click();
    await expect(page.getByText('ui-live-smoke created.')).toBeVisible();

    const routeResponse = await request.get(`${base}/v1/routes/http/ui-live-smoke`, { headers: authorization });
    expect(routeResponse.ok()).toBeTruthy();
    const created = await routeResponse.json();
    expect(created).toMatchObject({
      cache: { ttl_seconds: 30, max_ttl_seconds: 60 }, require_tls: true, retries: 2, upstream_timeout_ms: 120000, path_match: 'segment_prefix',
      balance: { mode: 'least_connections', weights: [3, 1], health: { failure_threshold: 3, cooldown_ms: 15000 } },
      auth: { url: 'https://auth.internal/check', request_headers: [], response_headers: ['x-user'], timeout_ms: 1000, forward_response: true },
      basic_auth: { realm: 'ops', credentials: [credential], hide_credentials: true, identity_header: 'x-authenticated-user' },
      response_set_headers: { 'x-frame-options': 'DENY' }, response_remove_headers: ['server'],
    });

    // The editor shows the stored values, and a server-side rejection surfaces the validator's real reason.
    await page.getByRole('searchbox', { name: 'Search HTTP routes' }).fill('ui-live-smoke');
    await page.getByRole('heading', { name: 'ui-live-smoke' }).locator('..').locator('..').getByRole('button', { name: 'Edit' }).click();
    await expect(page.getByLabel('Require TLS')).toBeChecked();
    await expect(page.getByLabel('Credentials', { exact: true })).toHaveValue(credential);
    await expect(page.getByLabel('Backend weights')).toHaveValue('3, 1');
    await page.getByLabel('Upstream Host override').fill('bad host');
    await page.getByRole('button', { name: 'Save route' }).click();
    await expect(page.locator('#route-message')).toContainText('invalid upstream_host');
    await page.getByLabel('Upstream Host override').fill('');
    await page.getByRole('button', { name: 'Delete route' }).click();
    await page.getByRole('dialog', { name: 'Delete route?' }).getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('ui-live-smoke deleted.')).toBeVisible();

    await page.getByRole('link', { name: 'Cache', exact: true }).click();
    await page.getByLabel('Global cache policy JSON').fill('null');
    await page.getByRole('button', { name: 'Apply cache policy' }).click();
    await expect(page.locator('#cache-message')).toContainText('Cache policy is active');
    await expect(page.locator('#cache-state')).toHaveText('Disabled');

    const finalConfigResponse = await request.get(`${base}/v1/config`, { headers: authorization });
    expect(finalConfigResponse.ok()).toBeTruthy();
    const finalConfig = await finalConfigResponse.json();
    expect(finalConfig.cache).toBeNull();
    expect(finalConfig.http.some(route => route.id === 'ui-live-smoke')).toBe(false);
    const disabledCacheResponse = await request.get(`${base}/v1/cache`, { headers: authorization });
    expect(disabledCacheResponse.ok()).toBeTruthy();
    expect(await disabledCacheResponse.json()).toMatchObject({ enabled: false, config: null, stats: null, active_fills: 0 });
  });

  test('domain group created in the UI remains one native route with shared policy', async ({ page, request }) => {
    const authorization = { Authorization: `Bearer ${token}` };
    await page.goto(`${base}/ui/`);
    if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
      await page.getByRole('button', { name: 'Use administrator token' }).click();
    }
    await page.getByLabel('Administrator token').fill(token);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#connection-state')).toHaveText('Connected');

    await page.getByRole('link', { name: 'HTTP routes' }).click();
    await page.locator('#view-http > .page-head').getByRole('button', { name: 'New HTTP route' }).click();
    await page.getByLabel('Route ID').fill('shared-domains');
    await page.getByLabel('Host selection mode').selectOption('group');
    await page.getByLabel('Domain group hosts').fill('foo.example.test\nwww.foo.example.test');
    await page.getByLabel('Backends').fill('http://127.0.0.1:65534');
    await openSection(page, 'Response headers');
    await page.getByLabel('Set response headers').fill('x-shared-policy: first');
    await page.getByRole('button', { name: 'Create route' }).click();
    await expect(page.getByText('shared-domains created.')).toBeVisible();

    const listed = await request.get(`${base}/v1/routes/http`, { headers: authorization });
    expect(listed.status()).toBe(200);
    const routes = (await listed.json()).routes;
    expect(routes.filter(route => route.id === 'shared-domains')).toHaveLength(1);
    expect(routes.find(route => route.id === 'shared-domains')).toMatchObject({
      host: null,
      hosts: ['foo.example.test', 'www.foo.example.test'],
      backends: ['http://127.0.0.1:65534'],
      response_set_headers: { 'x-shared-policy': 'first' },
    });

    await page.getByRole('searchbox', { name: 'Search HTTP routes' }).fill('shared-domains');
    const row = page.locator('#http-routes tr[data-route-id="shared-domains"]');
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(page.getByLabel('Host selection mode')).toHaveValue('group');
    await expect(page.getByLabel('Domain group hosts')).toHaveValue('foo.example.test\nwww.foo.example.test');
    await expect(page.getByLabel('Backends')).toHaveValue('http://127.0.0.1:65534');
    await expect(page.getByLabel('Set response headers')).toHaveValue('x-shared-policy: first');
    await page.getByLabel('Domain group hosts').fill('foo.example.test\nwww.foo.example.test\napi.example.test');
    await page.getByLabel('Set response headers').fill('x-shared-policy: second');
    await page.getByRole('button', { name: 'Save route' }).click();
    await expect(page.getByText('shared-domains updated.')).toBeVisible();

    const updated = await request.get(`${base}/v1/routes/http/shared-domains`, { headers: authorization });
    expect(updated.status()).toBe(200);
    expect(await updated.json()).toMatchObject({
      hosts: ['foo.example.test', 'www.foo.example.test', 'api.example.test'],
      backends: ['http://127.0.0.1:65534'],
      response_set_headers: { 'x-shared-policy': 'second' },
    });
    await page.locator('#http-routes tr[data-route-id="shared-domains"]').getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('button', { name: 'Delete route' }).click();
    await page.getByRole('dialog', { name: 'Delete route?' }).getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('shared-domains deleted.')).toBeVisible();
    const after = await request.get(`${base}/v1/routes/http`, { headers: authorization });
    expect((await after.json()).routes.some(route => route.id === 'shared-domains')).toBe(false);
  });

  test('native TCP completion policy publishes to the real API and removal preserves other configuration', async ({ page, request }) => {
    const authorization = { Authorization: `Bearer ${token}` };
    const originalResponse = await request.get(`${base}/v1/config`, { headers: authorization });
    expect(originalResponse.status()).toBe(200);
    const original = await originalResponse.json();
    expect(original.settings?.tcp_recent_recording ?? null).toBeNull();
    await page.goto(`${base}/ui/`);
    if (await page.getByRole('button', { name: 'Use administrator token' }).isVisible()) {
      await page.getByRole('button', { name: 'Use administrator token' }).click();
    }
    await page.getByLabel('Administrator token').fill(token);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#connection-state')).toHaveText('Connected');
    await page.locator('[data-view="config"]').click();
    const panel = page.locator('#tcp-recording-section');
    if (!(await panel.evaluate(element => element.open))) await panel.locator('summary').click();
    await page.locator('#tcp-recording-enabled').check();
    await page.locator('#tcp-recording-add').click();
    const card = page.locator('#tcp-recording-rules .user-card').first();
    await card.getByLabel('Rule ID').fill('retired-echo');
    await card.getByLabel('Action').selectOption('drop');
    // A policy can retain a listener address after the listener is removed.
    await card.getByLabel('Listen addresses (one IP:port per line)').fill('127.0.0.1:15432');
    await card.getByLabel('Outcomes (one code per line)').fill('eof');
    await page.locator('#apply-config').click();
    await expect(page.locator('#config-message')).toContainText(`Revision ${original.revision + 1} is active`);
    const savedResponse = await request.get(`${base}/v1/config`, { headers: authorization });
    const saved = await savedResponse.json();
    expect(saved.settings.tcp_recent_recording).toMatchObject({ default_action: 'record', rules: [{
      id: 'retired-echo', action: 'drop', match: { listen_addresses: ['127.0.0.1:15432'], outcomes: ['eof'] },
    }] });
    const withoutRecording = value => {
      const copy = structuredClone(value); delete copy.revision;
      if (copy.settings) {
        delete copy.settings.tcp_recent_recording;
        if (!Object.keys(copy.settings).length) delete copy.settings;
      }
      return copy;
    };
    expect(withoutRecording(saved)).toEqual(withoutRecording(original));
    await page.locator('#locale-select').selectOption('ko');
    await expect(panel.locator('summary')).toContainText('TCP');
    await page.locator('#locale-select').selectOption('en');
    await page.locator('#tcp-recording-enabled').uncheck();
    await page.locator('#apply-config').click();
    await expect(page.locator('#config-message')).toContainText(`Revision ${original.revision + 2} is active`);
    const restored = await (await request.get(`${base}/v1/config`, { headers: authorization })).json();
    expect(restored.settings?.tcp_recent_recording ?? null).toBeNull();
    expect(withoutRecording(restored)).toEqual(withoutRecording(original));
  });

});
