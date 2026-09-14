import { test, expect } from '@playwright/test';

const http = Array.from({ length: 61 }, (_, index) => ({
  id: `route-${String(index).padStart(2, '0')}`,
  priority: index < 2 ? 10 : 0,
  host: `node${String(index).padStart(2, '0')}.example.test`,
  path_prefix: '/',
  backends: [`https://upstream${String(index).padStart(2, '0')}.internal:443`],
  require_tls: index === 1,
  auth: index === 1 ? { url: 'https://auth.internal/check' } : null,
  cache: index === 2 ? { ttl_seconds: 30 } : null,
  deny_cidrs: index === 3 ? ['192.0.2.0/24'] : [],
}));
const tcp = [
  { id: 'tcp-a', priority: 5, listen: '127.0.0.1:9001', sni: { hosts: ['db.example.test'] }, backends: ['db.internal:5432'], upstream: { tls: { server_name: 'db.internal' } }, deny_cidrs: [] },
  { id: 'tcp-b', priority: 5, listen: '127.0.0.1:9001', sni: { host_regexes: ['^cache[0-9]+[.]example[.]test$'] }, backends: ['cache.internal:6379'], upstream: { socks5: { address: 'proxy.internal:1080' } }, deny_cidrs: [] },
  { id: 'tcp-c', priority: 0, listen: '127.0.0.1:9002', sni: null, backends: ['other.internal:9000'], deny_cidrs: ['198.51.100.0/24'] },
];

async function setup(page, httpRoutes = http) {
  await page.route('**/*', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: httpRoutes.length, tcp_routes: tcp.length, metrics: {}, state: { draining: false }, uptime_seconds: 1, version: 'test', process_id: 1 } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/routes/http') return route.fulfill({ json: { revision: 7, routes: httpRoutes }, headers: { etag: '"7"' } });
    if (path === '/v1/routes/tcp') return route.fulfill({ json: { revision: 7, routes: tcp }, headers: { etag: '"7"' } });
    for (const [type, routes] of [['http', httpRoutes], ['tcp', tcp]]) {
      const prefix = `/v1/routes/${type}/`;
      if (path.startsWith(prefix)) {
        const found = routes.find((item) => item.id === decodeURIComponent(path.slice(prefix.length)));
        return route.fulfill({ json: found, headers: { etag: '"7"' } });
      }
    }
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-submit').click();
  await expect(page.getByRole('dialog', { name: 'Connect to this proxy' })).toBeHidden();
}

test('HTTP inventory pages, searches host ID and upstream, and preserves priority ties', async ({ page }) => {
  await setup(page);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  const view = page.locator('#http-routes');
  await expect(view.locator('table.route-table')).toHaveCount(1);
  await expect(view.locator('tbody tr')).toHaveCount(25);
  await expect(view.locator('.route-count')).toHaveText('61 routes');
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'route-00');
  await expect(view.locator('tbody tr').nth(1)).toHaveAttribute('data-route-id', 'route-01');
  await view.locator('.route-page-next').click();
  await expect(view.locator('.route-page-range')).toContainText('Showing 26–50 of 61');
  await view.locator('.route-search').fill('NODE01.EXAMPLE.TEST');
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'route-01');
  await expect(view.locator('.route-page-range')).toContainText('page 1 of 1');
  await view.locator('.route-search').fill('route-02');
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'route-02');
  await view.locator('.route-search').fill('upstream03.internal');
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'route-03');
  await view.locator('.route-search').fill('no-such-route');
  await expect(view.locator('.route-empty')).toContainText('No matching routes');
  await view.getByRole('button', { name: 'Clear filters' }).click();
  await expect(view.locator('tbody tr')).toHaveCount(25);
});

test('HTTP policy filters and stable sorting retain the Edit action', async ({ page }) => {
  await setup(page);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  const view = page.locator('#http-routes');
  await view.locator('.route-policy-filter').selectOption('auth');
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr')).toContainText('TLS required');
  await view.locator('tbody tr').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog-title')).toHaveText('Edit route-01');
  await page.locator('#route-dialog').evaluate((dialog) => dialog.close());
  await view.locator('.route-policy-filter').selectOption('all');
  await view.locator('.route-sort').selectOption('id-desc');
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'route-60');
  await view.locator('.route-page-size').selectOption('100');
  await expect(view.locator('tbody tr')).toHaveCount(61);
  await expect(view.locator('.route-page-next')).toBeDisabled();
});

test('TCP inventory supports SNI and upstream policy filters', async ({ page }) => {
  await setup(page);
  await page.getByRole('link', { name: 'TCP routes' }).click();
  const view = page.locator('#tcp-routes');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'tcp-a');
  await expect(view.locator('tbody tr').nth(1)).toHaveAttribute('data-route-id', 'tcp-b');
  await view.locator('.route-policy-filter').selectOption('sni');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await view.locator('.route-policy-filter').selectOption('tls');
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'tcp-a');
  await view.locator('.route-policy-filter').selectOption('upstream');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await view.locator('.route-search').fill('cache.internal');
  await expect(view.locator('tbody tr').first()).toHaveAttribute('data-route-id', 'tcp-b');
});

test('HTTP inventory distinguishes same-host listener scopes including disabled and workload routes', async ({ page }) => {
  const shared = { host: 'api.example.test', path_prefix: '/', backends: ['http://127.0.0.1:8080'] };
  const routes = [
    { ...shared, id: 'legacy', listener_ids: [] },
    { ...shared, id: 'named', listener_ids: ['edge'], enabled: false },
    { ...shared, id: 'both', listener_ids: ['default', 'edge'] },
    { ...shared, id: 'private', workload_auth: { listener_ids: ['orders'] } },
  ];
  await setup(page, routes);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  const view = page.locator('#http-routes');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  await expect(view.locator('[data-route-id="legacy"] .route-listener-scope')).toHaveText('Public listeners: Default CLI listener');
  await expect(view.locator('[data-route-id="named"] .route-listener-scope')).toHaveText('Public listeners: edge');
  await expect(view.locator('[data-route-id="named"]')).toContainText('Disabled');
  await expect(view.locator('[data-route-id="both"] .route-listener-scope')).toHaveText('Public listeners: Default CLI listener, edge');
  await expect(view.locator('[data-route-id="private"] .route-listener-scope')).toHaveText('Workload mTLS listeners: orders');
  const search = view.locator('.route-search');
  await expect(search).toHaveAttribute('placeholder', 'Search host, ID, listener, or upstream');
  await search.fill('default');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('[data-route-id="private"]')).toHaveCount(0);
  await search.fill('edge');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await search.fill('orders');
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr')).toHaveAttribute('data-route-id', 'private');
});

test('Korean HTTP inventory keeps listener IDs and translates scope semantics', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'language', { configurable: true, get: () => 'ko-KR' }));
  const shared = { host: 'api.example.test', path_prefix: '/', backends: ['http://127.0.0.1:8080'] };
  await setup(page, [
    { ...shared, id: 'legacy', listener_ids: [] },
    { ...shared, id: 'edge', listener_ids: ['default', 'public-edge'] },
    { ...shared, id: 'private', workload_auth: { listener_ids: ['orders'] } },
  ]);
  await page.locator('[data-view="http"]').click();
  const view = page.locator('#http-routes');
  await expect(view.locator('[data-route-id="legacy"] .route-listener-scope')).toContainText('기본 CLI 리스너');
  await expect(view.locator('[data-route-id="edge"] .route-listener-scope')).toContainText('public-edge');
  await expect(view.locator('[data-route-id="private"] .route-listener-scope')).toContainText('워크로드 mTLS 리스너: orders');
  await expect(view.locator('.route-search')).toHaveAttribute('placeholder', '호스트, ID, 리스너 또는 업스트림 검색');
  await view.locator('.route-search').fill('public-edge');
  await expect(view.locator('tbody tr')).toHaveCount(1);
});
