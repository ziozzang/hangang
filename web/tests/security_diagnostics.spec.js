import { test, expect } from '@playwright/test';

const status = (metrics) => ({ revision: 1, http_routes: 0, tcp_routes: 0, uptime_seconds: 1,
  state: { ready: true }, metrics: { requests_total: 0, errors_total: 0, ...metrics } });

async function openStatus(page, initial, next = null) {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await page.route('**/*', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return route.fulfill({ json: initial });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/events') {
      await gate;
      return route.fulfill({ contentType: 'text/event-stream', body: next ? `event: status\ndata: ${JSON.stringify(next)}\n\n` : '' });
    }
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-admin-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return release;
}

test('security diagnostics group current counters, update live, and translate', async ({ page }) => {
  const initial = status({ jwt_auth_rejections_total: 0, jwt_auth_unavailable_total: 2,
    jwt_auth_capacity_rejections_total: -1, http_mtls_rejections_total: 3,
    http_mtls_lease_terminations_total: 4, workload_auth_rejections_total: 5,
    workload_route_terminations_total: 6, tcp_mtls_rejections_total: 7,
    tcp_mtls_lease_terminations_total: 8, jwt_lease_terminations_total: 9 });
  const next = status({ ...initial.metrics, jwt_auth_rejections_total: 10, jwt_auth_unavailable_total: 0 });
  const release = await openStatus(page, initial, next);
  const grid = page.locator('#security-diagnostics-grid');
  await expect(grid.locator('.security-diagnostics-row')).toHaveCount(9);
  await expect(grid.locator('[data-metric="jwt_auth_rejections_total"] strong')).toHaveText('0');
  await expect(grid.locator('[data-metric="jwt_auth_unavailable_total"] strong')).toHaveText('2');
  await expect(grid.locator('[data-metric="jwt_auth_capacity_rejections_total"] strong')).toHaveText('—');
  await expect(grid.locator('[data-metric="http_mtls_lease_terminations_total"] strong')).toHaveText('4');
  await expect(grid).not.toContainText('JWT stream terminations');
  release();
  await expect(grid.locator('[data-metric="jwt_auth_rejections_total"] strong')).toHaveText('10');
  await expect(grid.locator('[data-metric="jwt_auth_unavailable_total"] strong')).toHaveText('0');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#security-diagnostics-title')).toHaveText('보안 진단');
  await expect(grid).toContainText('JWT 인증 거부');
  await expect(grid).toContainText('기존 스트림 종료');
});

test('missing and unsafe counts remain unknown', async ({ page }) => {
  await openStatus(page, status({ jwt_auth_rejections_total: '0', tcp_mtls_rejections_total: 1.5 }));
  const grid = page.locator('#security-diagnostics-grid');
  await expect(grid.locator('.security-diagnostics-row')).toHaveCount(9);
  await expect(grid.locator('strong')).toHaveText(Array(9).fill('—'));
});
