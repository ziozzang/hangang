import { test, expect } from '@playwright/test';

test('HTTP backend reachability uses observations, never eligibility alone, and appears in editor', async ({ page }) => {
  await page.clock.install();
  let observationsFetched = 0;
  const backends = ['http://unknown:8080', 'http://healthy:8080', 'http://failed:8080', 'http://checking:8080', 'http://stale:8080'];
  const site = { id: 'site', host: 'example.test', path_prefix: '/', backends, headers: {}, json: {} };
  const rows = backends.map((address, backend_index) => ({ protocol: 'http', route_id: 'site', address, backend_index, enabled: true, available: true, health_mode: 'unmonitored', probe_observed: null, initial_check_pending: null }));
  rows[1].last_observation = { source: 'passive', kind: 'http_response', status: 500, age_ms: 2000, observed_at_unix_ms: Date.now() - 2000 }; rows[1].available = false;
  rows[2].last_observation = { source: 'passive', kind: 'timeout', status: null, age_ms: 1000, observed_at_unix_ms: Date.now() - 1000 };
  rows[3].initial_check_pending = true;
  rows[4].last_observation = { source: 'passive', kind: 'http_response', status: 200, age_ms: 60001, observed_at_unix_ms: Date.now() - 60001 };
  await page.route('**/*', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (path === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 1, tcp_routes: 0, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: '' });
    if (path === '/v1/routes/http') return route.fulfill({ json: { revision: 7, routes: [site] } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 7, http: [site], tcp: [] } });
    if (path === '/v1/routes/http/site') return route.fulfill({ json: site });
    if (path === '/v1/operations') { observationsFetched++; return route.fulfill({ json: { revision: 7, total: 5, rows } }); }
    return route.fulfill({ status: 404, body: '' });
  });
  await page.goto('/ui/'); await page.locator('#token-input').fill('fixture'); await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden(); await page.locator('[data-view="http"]').click();
  const inventory = page.locator('#http-routes');
  await expect(inventory.locator('[data-reachability="unknown"]')).toHaveCount(2);
  await expect(inventory.locator('[data-reachability="unknown"]').first()).toHaveText('Unknown');
  await expect(inventory.locator('[data-reachability="reachable"]')).toContainText('HTTP 500');
  await expect(inventory.locator('[data-reachability="timed out"]')).toContainText('Timed out');
  await expect(inventory.locator('[data-reachability="checking"]')).toHaveText('Checking');
  await page.locator('[data-route-id="site"] td:last-child button').first().click();
  await expect(page.locator('.backend-runtime-status [data-reachability="unknown"]').first()).toHaveText('Unknown');
  await expect(page.locator('.backend-runtime-status [data-reachability="reachable"]')).toContainText('2s ago');
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.locator('.backend-runtime-status [data-reachability="unknown"]').first()).toHaveText('알 수 없음');
  await expect(page.locator('.backend-runtime-status [data-reachability="reachable"]')).toContainText('연결 가능');
  const fetched = observationsFetched;
  await page.clock.fastForward(65000);
  await expect(page.locator('.backend-runtime-status [data-reachability="reachable"]')).toHaveCount(0);
  await expect(page.locator('.backend-runtime-status [data-reachability="unknown"]')).toHaveCount(4);
  expect(observationsFetched).toBe(fetched);
});
