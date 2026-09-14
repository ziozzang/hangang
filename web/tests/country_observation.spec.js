import { test, expect } from '@playwright/test';

const digest = 'a'.repeat(64);
const token = 'fixture-country-admin-token';
const record = (id, geoip) => ({
  id, timestamp_unix_ms: Date.now(), peer_ip: '192.0.2.4', peer_port: 44000,
  client_ip: '198.51.100.9', method: 'GET', path: `/country-${id}`,
  route_id: 'api', status: 200, response_head_ms: 12, protocol: 'HTTP/1.1', tls: true,
  ...(geoip === undefined ? {} : { geoip }),
});

async function fixture(page, records, { retention = 60, geoipMetrics } = {}) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push(url.pathname);
    if (url.pathname === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'missing' });
    if (url.pathname === '/v1/auth/logout') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/v1/status') return route.fulfill({ json: {
      revision: 1, http_routes: 1, tcp_routes: 0, uptime_seconds: 10,
      version: 'fixture', process_id: 4, state: { ready: true, draining: false },
      metrics: { requests_total: 1, errors_total: 0, active_connections: 0 },
      ...(geoipMetrics ? { geoip_metrics: geoipMetrics } : {}),
    } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/traffic') return route.fulfill({ json: {
      records, oldest_id: records[0]?.id ?? null, latest_id: records.at(-1)?.id ?? 0,
      next_after: records.at(-1)?.id ?? 0, gap: false, dropped_total: 0,
      retention_seconds: retention, server_time_unix_ms: Date.now(),
    } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'unavailable' });
    if (url.pathname === '/v1/config') return route.fulfill({ json: { revision: 1, http: [], tcp: [] } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return calls;
}

test('traffic renders bounded GeoIP observations and filters country and exact state', async ({ page }) => {
  const malicious = '<img src=x onerror="window.__geoInjected=1">';
  const calls = await fixture(page, [
    record(1, { state: 'known', country: 'KR', generation_sha256: digest, error_code: null }),
    record(2, { state: 'unknown', country: null, generation_sha256: digest, error_code: null }),
    record(3, { state: 'unavailable', country: null, generation_sha256: null, error_code: 'pending' }),
    record(4, { state: 'not_configured', country: null, generation_sha256: null, error_code: null }),
    record(5), // An older server has no geoip field; this is not a country miss.
    record(6, { state: 'known', country: malicious, generation_sha256: digest, error_code: null }),
  ]);
  const rows = page.locator('#activity-rows tr');
  await expect(rows).toHaveCount(6);
  await expect(rows.nth(5).locator('.geoip-observation')).toHaveText('Country estimate: KR');
  await expect(rows.nth(5).locator('.geoip-observation')).toHaveAttribute('title', `Database generation SHA-256: ${digest}`);
  await expect(rows.nth(4).locator('.geoip-observation')).toHaveText('Country estimate: unknown');
  await expect(rows.nth(3).locator('.geoip-observation')).toHaveText('GeoIP unavailable (pending)');
  await expect(rows.nth(2).locator('.geoip-observation')).toHaveText('GeoIP not configured');
  await expect(rows.nth(1).locator('.geoip-observation')).toHaveText('GeoIP not checked');
  await expect(rows.nth(0).locator('.geoip-observation')).toHaveText('GeoIP not checked');
  await expect(page.locator('#activity-rows img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__geoInjected)).toBeUndefined();

  await page.locator('#activity-search').fill('country:kr');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('/country-1');
  await page.locator('#activity-search').fill('state:known');
  await expect(rows).toHaveCount(1); // Does not accidentally include unknown.
  await page.locator('#activity-search').fill('state:unknown');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('/country-2');
  await page.locator('#activity-search').fill('pending');
  await expect(rows).toHaveCount(1);
  await page.locator('#activity-search').fill('state:not_checked');
  await expect(rows).toHaveCount(2);

  // No per-row lookup, and flat status metrics cannot fabricate labeled country counters.
  expect(calls).not.toContain('/v1/geoip/lookup');
  await expect(page.locator('#prometheus-rows')).not.toContainText('geoip_country_requests_total');
});

test('paused GeoIP labels follow locale, then expire and scrub on logout', async ({ page }) => {
  await fixture(page, [record(1, { state: 'known', country: 'KR', generation_sha256: digest, error_code: null })], { retention: 2 });
  const rows = page.locator('#activity-rows tr');
  await expect(rows).toHaveCount(1);
  await page.locator('#activity-pause').click();
  await page.locator('#locale-select').selectOption('ko');
  await expect(rows.first().locator('.geoip-observation')).toHaveText('추정 국가: KR');
  await expect(rows.first().locator('.geoip-observation')).toHaveAttribute('title', `데이터베이스 세대 SHA-256: ${digest}`);
  await expect(rows).toHaveCount(0, { timeout: 5000 });
  await page.getByRole('button', { name: '로그아웃' }).click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(rows).toHaveCount(0);
  await expect(page.locator('#activity-rows')).not.toContainText(digest);
  await expect(page.locator('#geoip-metrics')).toHaveCount(0); // Old status had no aggregate field.
});

test('status GeoIP counters separate HTTP/TCP lookup outcomes from enforced decisions', async ({ page }) => {
  const geoipMetrics = {
    http: { known: 7, unknown: 2, unavailable: 1, allowed: 3, denied: 4, admission_unavailable: 1,
      countries: { KR: 5, US: 2, unknown: 2 } },
    tcp: { known: 1, unknown: 0, unavailable: 3, allowed: 0, denied: 1, admission_unavailable: 2,
      countries: { GB: 1 } },
  };
  await fixture(page, [], { geoipMetrics });
  const cards = page.locator('#geoip-metrics .metric');
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0)).toContainText('HTTP');
  await expect(cards.nth(0)).toContainText('known 7 · unknown 2 · unavailable 1');
  await expect(cards.nth(0)).toContainText('allowed 3 · denied 4 · unavailable 1');
  await expect(cards.nth(0)).toContainText('KR 5');
  await expect(cards.nth(1)).toContainText('TCP');
  await expect(cards.nth(1)).toContainText('known 1 · unknown 0 · unavailable 3');
  await expect(cards.nth(1)).toContainText('allowed 0 · denied 1 · unavailable 2');
  await expect(cards.nth(1)).toContainText('GB 1');
  await page.locator('#locale-select').selectOption('ko');
  await expect(cards.nth(0)).toContainText('조회 · 국가 확인 7 · 국가 미확인 2 · 조회 불가 1');
  await expect(cards.nth(0)).toContainText('적용된 정책 · 허용 3 · 거부 4 · 조회 불가 1');
  await page.evaluate(async () => {
    const { recordStatus } = await import('/ui/console.js');
    recordStatus({ revision: 1, http_routes: 1, tcp_routes: 0, uptime_seconds: 11,
      version: 'fixture', process_id: 4, state: { ready: true, draining: false },
      metrics: { requests_total: 2, errors_total: 0, active_connections: 0 },
      geoip_metrics: {
        http: { known: 8, unknown: 2, unavailable: 1, allowed: 3, denied: 5, admission_unavailable: 1, countries: { KR: 6, US: 2, unknown: 2 } },
        tcp: { known: 1, unknown: 0, unavailable: 3, allowed: 0, denied: 1, admission_unavailable: 2, countries: { GB: 1 } },
      },
    });
  });
  await expect(cards.nth(0)).toContainText('국가 확인 8');
  await expect(cards.nth(0)).toContainText('거부 5');
  await expect(cards.nth(0)).toContainText('KR 6');
  await page.getByRole('button', { name: '로그아웃' }).click();
  await expect(page.locator('#geoip-metrics')).toHaveCount(0);
});
