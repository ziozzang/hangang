import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = path.join(web, 'test-results', 'zero-trust-screens');

function event(index, overrides = {}) {
  const deny = index % 2 === 0;
  return {
    schema: 'hangang.decision.v1', event_id: `01JA9Q4Z8M3V7T2C6R1K5N0P${String(index).padStart(2, '0')}`, kind: 'enforced',
    request_id: `hg-${String(index).padStart(16, '0')}`, time: new Date(Date.UTC(2026, 9, 16, 9, 12, 44 - index)).toISOString(),
    route: { route_id: 'app-api', host: 'app.example.test', path_template: '/api/reports/', method: 'GET', service: 'reports', resource: 'report', action: 'read' },
    outcome: deny ? { result: 'deny', status: 403, deciding_stage: 'authorization', reason: 'pumgye.class_denied', message_key: 'decision.reason.pumgye.class_denied' } : { result: 'allow', status: 200, deciding_stage: 'enforcement', reason: 'hangang.allowed' },
    stages: [
      { stage: 'network', authority: 'sumunjang', verdict: 'allow', mode: 'enforce', rules: [], revision: 418, latency_us: 41, transport: 'grpc', client: { ip_ref: 'ip~4MZQ7K2V9B4MZQ7K', prefix_ref: 'pfx~Q1W8Q1W8Q1W8Q1W8', asn: 64500, country: 'KR', sealed: false } },
      { stage: 'identity', authority: 'hopae', verdict: 'authenticated', subject_ref: 'sub~7HC2LQ0D5E7HC2LQ', subject_sealed: false, principal: 'human', aal: 1, factors: ['federated'], latency_us: 183, transport: 'hop1' },
      ...(deny ? [{ stage: 'authorization', authority: 'pumgye', decision: 'ClassDenied', roles: [], information_class: 'restricted', revision: 77, latency_us: 22, transport: 'grpc' }] : []),
      { stage: 'enforcement', authority: 'hangang', action: deny ? 'refused' : 'forwarded', obligations: [], fence: deny ? 'unspecified' : 'ok', revision: 268 },
    ],
    revisions: { hangang: 268, sumunjang: 418, ...(deny ? { pumgye: 77 } : {}) },
    sampling: { class: deny ? 'deny' : 'allow', rate: deny ? 1 : 0.01 }, privacy: { profile: 'strict', key_epoch: '2026-10-16' },
    ...(deny ? {} : { estimate_weight: 100 }), ...overrides,
  };
}

async function setup(page, { disabled = false, resolve = 'ok', auditFailure = false, pumgyeFailure = false, hopaeEvents = false, guardAudit = false } = {}) {
  const calls = [];
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    calls.push({ path: p, query: url.search, method: request.method(), body: request.postData() });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: [] } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 270, http_routes: 1, tcp_routes: 0, metrics: {}, uptime_seconds: 1, state: {} } });
    if (p === '/v1/pumgye/status') return pumgyeFailure ? route.fulfill({ status: 503, json: { detail: 'authority unavailable' } }) : route.fulfill({ json: { revision: 78 } });
    if (p === '/v1/observability/status') return route.fulfill({ json: disabled ? { state: 'disabled', profile: 'off' } : { state: 'enabled', profile: 'strict', exporter: { connected: true }, rings: { shards: 2, deny_slots: 16384, allow_slots: 8192, queued: 0 }, keys: { current_epoch: '2026-10-16', epochs: 2 }, counters: { dropped: { ring_full_deny: 0, ring_full_allow: 3, exporter_unavailable: 0, no_key: 0, invalid: 0 } }, store: { rows: 9, newest_event_ms: Date.now() - 2000 } } });
    if (p === '/v1/observability/decisions') {
      if (disabled) return route.fulfill({ json: { state: 'disabled', profile: 'off' } });
      const cursor = url.searchParams.get('cursor');
      const items = cursor ? [event(4), event(5)] : [event(0), event(1), event(2), event(3)];
      return route.fulfill({ json: { state: 'enabled', profile: 'strict', items, next_cursor: cursor ? null : 'c'.repeat(48) } });
    }
    if (p === '/v1/observability/decisions/facets') {
      if (disabled) return route.fulfill({ json: { state: 'disabled' } });
      const denyOnly = url.searchParams.get('outcome') === 'deny';
      return route.fulfill({ json: { state: 'enabled', facets: {
        outcome: denyOnly ? [{ value: 'deny', events: 30, estimated_requests: 30 }] : [{ value: 'allow', events: 7, estimated_requests: 700 }, { value: 'deny', events: 30, estimated_requests: 30 }, { value: 'challenge', events: 5, estimated_requests: 5 }],
        reason: [{ value: 'pumgye.class_denied', events: 20, estimated_requests: 20 }, { value: 'sumunjang.network_denied', events: 10, estimated_requests: 10 }],
        route: [{ value: 'app-api', events: 30, estimated_requests: 30 }], country: [{ value: 'KR', events: 30, estimated_requests: 30 }],
        sampled: [{ value: 'deny', events: 28, estimated_requests: 28 }, { value: 'suppressed', events: 2, estimated_requests: 410 }] } } });
    }
    if (p === '/v1/observability/decisions/timeseries') return route.fulfill({ json: disabled ? { state: 'disabled' } : { state: 'enabled', bucket_seconds: 300, points: [{ start_ms: 1, outcome: 'deny', events: 2, estimated_requests: 2 }, { start_ms: 1, outcome: 'allow', events: 2, estimated_requests: 200 }, { start_ms: 2, outcome: 'deny', events: 10, estimated_requests: 10 }, { start_ms: 2, outcome: 'allow', events: 1, estimated_requests: 100 }] } });
    if (p.startsWith('/v1/observability/requests/')) return route.fulfill({ json: { state: 'enabled', request_id: decodeURIComponent(p.split('/').pop()), events: [event(0)] } });
    if (p === '/v1/plugins/hopae/subjects/resolve') {
      if (resolve === 'missing') return route.fulfill({ status: 404, json: { detail: 'unknown operation' } });
      const directory = {
        u_kim: { status: 'active', reason: null, kind: 'human', user_id: 'u_kim', display_name: 'Kim Analyst', email: 'k***@corp.example', providers: ['oidc-corp'], created_at: 1760000000, last_login_at: 1760600000, last_seen_at: 1760605000 },
        u_gone: { status: 'deleted', reason: null, kind: 'human', user_id: 'u_gone' },
        u_never: { status: 'unknown', reason: 'not_found', kind: null },
      };
      const blank = { kind: null, user_id: null, human_subject: null, display_name: null, email: null, providers: [], created_at: null, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null };
      const ids = JSON.parse(request.postData()).ids;
      const items = ids.map(id => ({ ...blank, id, ...(directory[id] || { status: 'unknown', reason: 'unrecognized' }) }));
      return route.fulfill({ json: { items, resolved: items.filter(i => i.status !== 'unknown').length, unknown: items.filter(i => i.status === 'unknown').length, complete: true, privacy_profile: 'standard' } });
    }
    if (p === '/v1/plugins/hopae/subjects/search') {
      const body = JSON.parse(request.postData());
      return route.fulfill({ json: { items: body.q === 'kim' ? [{ id: 'u_kim', status: 'active', reason: null, kind: 'human', user_id: 'u_kim', human_subject: null, display_name: 'Kim Analyst', email: 'k***@corp.example', providers: ['oidc-corp'], created_at: 1, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null }, { id: 'u_kimold', status: 'disabled', reason: null, kind: 'human', user_id: 'u_kimold', human_subject: null, display_name: 'Kim Former', email: null, providers: [], created_at: 1, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null }] : [], next_cursor: null, privacy_profile: 'standard' } });
    }
    if (p === '/v1/audit/users') return auditFailure ? route.fulfill({ status: 503, json: { detail: 'store down' } }) : route.fulfill({ json: { records: [{ id: 5, time_unix_ms: Date.UTC(2026, 9, 16, 8), action: 'update', actor_kind: 'account', actor_user_id: 1, target_user_id: 2, before: { role: 'viewer', enabled: true }, after: { role: 'admin', enabled: true } }] } });
    if (p === '/v1/users') return route.fulfill({ json: { users: [{ id: 1, username: 'operator' }, { id: 2, username: 'kim' }] } });
    if (p === '/v1/plugins/audit') return route.fulfill({ json: { operations: [{ id: 9, started_at: Date.UTC(2026, 9, 16, 9) / 1000, completed_at: null, actor_name: 'operator', plugin: 'guard', path: 'policy', method: 'PUT', body_sha256: 'ab'.repeat(32), status: null }] } });
    if (p === '/v1/pumgye/audit') return route.fulfill({ json: [{ revision: 77, at_unix: Date.UTC(2026, 9, 16, 7) / 1000, actor: 'sha256:aa', sha256: 'cd'.repeat(32) }] });
    if (p === '/v1/plugins/guard/audit/query') return guardAudit ? route.fulfill({ json: { schema: 'sumunjang.audit.v1', entries: [
      { id: 'a118', time: 1760605000, time_ms: Date.UTC(2026, 9, 16, 9, 40), actor: { kind: 'delegated', id: 7, name: 'operator', issuer: 'hangang' }, action: 'policy.document.replace', target: 'policy', result: 'committed', revision_before: 41, revision_after: 42, policy_revision: 12, before_digest: 'sha256:' + 'aa'.repeat(32), after_digest: 'sha256:' + 'bb'.repeat(32), summary: 'mode observe -> enforce; allow +1: 192.0.2.0/24', reason: 'enable enforcement', message_key: 'sumunjang.audit.result.committed' },
      { id: 'a117', time: 1760604000, actor: { kind: 'credential' }, action: 'rules.lua.replace', target: 'rules', result: 'refused', revision_before: 41, revision_after: 41, before_digest: 'sha256:' + 'cc'.repeat(32), after_digest: null, summary: 'Lua compile error', error: 'syntax error near end' }],
      next_cursor: null, retention: { max_rows: 100000, max_days: 365, retained_rows: 2 } } }) : route.fulfill({ status: 404, json: { detail: 'unknown plugin route' } });
    if (p === '/v1/plugins/hopae/events/query') return hopaeEvents ? route.fulfill({ json: { items: [
      { event_id: 'e_1', at: Date.UTC(2026, 9, 16, 9, 30) / 1000, kind: 'admin.user_disable', outcome: 'success', reason: null, user_id: 'u_kim', session_id: null, attrs: { actor: 'u_admin', actor_session: 's_x', count: 3 } },
      { event_id: 'e_2', at: Date.UTC(2026, 9, 16, 9, 31) / 1000, kind: 'login.succeeded', outcome: 'success', reason: null, user_id: 'u_kim', attrs: {} },
      { event_id: 'e_3', at: Date.UTC(2026, 9, 16, 9, 32) / 1000, kind: 'admin.denied', outcome: 'failure', reason: null, user_id: 'u_bob', attrs: { endpoint: '/v1/users/{id}/disable', reason: 'role_insufficient' } }], next_cursor: null } }) : route.fulfill({ status: 404, json: { detail: 'unknown plugin route' } });
    if (p === '/v1/geoip/lookup') return route.fulfill({ json: { ip: '198.51.100.7', country: 'KR', revision: 1 } });
    return route.fulfill({ status: 404, json: { detail: 'not found' } });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return calls;
}

async function shot(page, name) {
  fs.mkdirSync(shots, { recursive: true });
  await page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true });
}

test('message catalogs pass the key-based i18n lint', () => {
  const output = execFileSync(process.execPath, [path.join(web, 'tools/lint-i18n.mjs')], { encoding: 'utf8' });
  expect(output).toContain('reason codes');
});

test('task sections replace component navigation and localize by key', async ({ page }) => {
  await setup(page);
  for (const name of ['Overview', 'Access', 'Identities', 'Policies', 'Network', 'Devices & Workloads', 'Audit', 'System']) {
    await expect(page.locator('.sidebar nav').getByRole('link', { name, exact: true })).toBeVisible();
  }
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('.sidebar nav').getByRole('link', { name: '접근', exact: true })).toBeVisible();
  await expect(page.locator('[data-zt-label="nav.components"]')).toHaveText('구성 요소 페이지');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('.sidebar nav').getByRole('link', { name: 'Access', exact: true })).toBeVisible();
});

test('decision log filters live in the URL, paginate by cursor and open request detail', async ({ page }) => {
  const calls = await setup(page);
  await page.locator('[data-view="access"]').click();
  const view = page.locator('#view-access');
  await expect(view.getByRole('heading', { name: 'Decision log' })).toBeVisible();
  await expect(view.locator('tbody tr')).toHaveCount(4);
  await expect(view.locator('tbody tr').first()).toContainText('No assigned role may access this information class.');
  await expect(view.getByRole('note')).toContainText('Strict privacy profile');
  await expect(view.locator('tbody tr').nth(1)).toContainText('sampled 1%');
  await view.getByLabel('Outcome').selectOption('deny');
  await view.getByLabel('User ID').fill('u_kim');
  await view.getByLabel('User ID').press('Enter');
  await expect(page).toHaveURL(/#access\/decisions\?outcome=deny&subject=u_kim$/);
  await expect.poll(() => calls.filter(c => c.path === '/v1/observability/decisions').at(-1)?.query).toContain('outcome=deny');
  expect(calls.filter(c => c.path === '/v1/observability/decisions').at(-1).query).toContain('subject=u_kim');
  await expect(view.getByLabel('Outcome')).toHaveValue('deny');
  await view.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(view.locator('tbody tr')).toHaveCount(2);
  expect(calls.filter(c => c.path === '/v1/observability/decisions').at(-1).query).toContain('cursor=' + 'c'.repeat(48));
  await view.getByRole('button', { name: 'Previous', exact: true }).click();
  await expect(view.locator('tbody tr')).toHaveCount(4);
  await page.goBack();
  await expect(page).toHaveURL(/#access$|#access\/decisions$/);
  await page.locator('#view-access .zt-search input').fill('hg-0000000000000000');
  await page.locator('#view-access .zt-search input').press('Enter');
  await expect(page).toHaveURL(/#access\/requests\/hg-0000000000000000$/);
  await shot(page, 'request-detail-en');
});

test('request detail shows the stage timeline with localized why and fix', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#access/requests/hg-0000000000000000');
  const view = page.locator('#view-access');
  await expect(view.getByRole('heading', { name: 'Request detail' })).toBeVisible();
  const stages = view.locator('.kit-stage');
  await expect(stages).toHaveCount(4);
  await expect(view.locator('.kit-stage.is-deciding')).toHaveAttribute('data-stage', 'authorization');
  await expect(view.locator('.kit-why')).toContainText('No assigned role may access this information class.');
  await expect(view.locator('.kit-fix')).toContainText('Grant the information class');
  await expect(view.locator('.zt-revisions [data-authority="pumgye"]')).toContainText('now 78');
  await expect(view.getByRole('button', { name: 'Re-run in simulator' })).toBeDisabled();
  await page.locator('#locale-select').selectOption('ko');
  await expect(view.getByRole('heading', { name: '요청 상세' })).toBeVisible();
  await expect(view.locator('.kit-why')).toContainText('이 정보 등급에 접근할 수 있는 역할이 없습니다.');
  await expect(view.locator('.kit-stage[data-stage="authorization"]')).toContainText('정보 등급 거부');
  await shot(page, 'request-detail-ko');
});

test('disabled decision events render as disabled, not empty', async ({ page }) => {
  await setup(page, { disabled: true });
  await page.locator('[data-view="access"]').click();
  await expect(page.locator('#view-access')).toContainText('Decision events disabled');
  await expect(page.locator('#view-access .kit-table')).toBeHidden();
  await page.locator('[data-view="overview"]').click();
  await expect(page.locator('#view-overview')).toContainText('Decision events disabled');
});

test('overview tiles link to the filtered log and failed sources are unavailable, not zero', async ({ page }) => {
  await setup(page, { pumgyeFailure: true });
  await page.locator('[data-view="overview"]').click();
  const view = page.locator('#view-overview');
  await expect(view.locator('.zt-kpi').first()).toContainText('735');
  const pumgye = view.locator('.zt-card', { hasText: 'Pumgye' });
  await expect(pumgye).toContainText('Status unavailable');
  await expect(pumgye.locator('[data-status="unavailable"]')).toBeVisible();
  await expect(view.locator('.zt-card', { hasText: 'Hopae' })).toContainText('Package not installed');
  await expect(view.locator('.zt-kpi-wide')).toContainText('2 buckets');
  await expect(view.locator('.zt-sparkline polyline')).toHaveCount(1);
  await expect(view.locator('.zt-top a').first()).toHaveAttribute('href', /#access\/decisions\?outcome=deny&reason=pumgye.class_denied/);
  await view.locator('.zt-kpi').nth(1).click();
  await expect(page).toHaveURL(/#access\/decisions\?outcome=deny$/);
});

test('unified audit federates sources, marks uncertain outcomes and labels partial failures', async ({ page }) => {
  await setup(page, { auditFailure: true });
  await page.locator('[data-view="audit"]').click();
  const view = page.locator('#view-audit');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.getByRole('alert')).toContainText('Console accounts');
  await expect(view.locator('tbody tr').first().locator('[data-status="uncertain"]')).toBeVisible();
  await expect(view.locator('.zt-sources')).toContainText('Not yet connected');
  await view.getByRole('combobox', { name: 'Source' }).selectOption('pumgye');
  await view.getByRole('button', { name: 'Apply filters' }).click();
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr').first()).toContainText('rev 77');
});

test('account audit shows a structured before/after diff', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#audit?source=accounts');
  const view = page.locator('#view-audit');
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expect(view.locator('tbody tr').first()).toContainText('Changed kim: role viewer → admin');
  await view.locator('tbody tr').first().click();
  await expect(view.locator('tbody tr').first()).toHaveAttribute('aria-expanded', 'true');
  await expect(view.locator('.kit-diff-change')).toContainText('role');
  await expect(view.locator('.kit-diff-change')).toContainText('"viewer" → "admin"');
});

test('subject resolution follows the Hopae directory contract and shows each state distinctly', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities/users/u_kim');
  const view = page.locator('#view-identities');
  await expect(view.locator('h1')).toHaveText('Kim Analyst');
  await expect(view.locator('[data-subject-state="active"]')).toContainText('Active');
  await expect(view).toContainText('k***@corp.example');
  await expect(view).toContainText('oidc-corp');
  expect(JSON.parse(calls.find(c => c.path === '/v1/plugins/hopae/subjects/resolve').body)).toEqual({ ids: ['u_kim'], privacy_profile: 'standard', include_groups: true });
  expect(calls.filter(c => c.path === '/v1/observability/decisions').at(-1).query).toContain('subject=u_kim');
  await page.evaluate(() => { location.hash = '#identities/users/u_gone'; });
  await expect(view.locator('[data-subject-state="deleted"]')).toContainText('Deleted (tombstone)');
  await expect(view.locator('h1')).toHaveText('u_gone');
  await expect(view).toContainText('no personal data');
  await page.evaluate(() => { location.hash = '#identities/users/u_never'; });
  await expect(view.locator('[data-subject-state="unknown"]')).toContainText('Unknown subject');
  await expect(view).toContainText('Hopae never issued this ID.');
  await page.locator('#locale-select').selectOption('ko');
  await expect(view.locator('[data-subject-state="unknown"]')).toContainText('알 수 없는 주체');
});

test('unavailable subject directory keeps the opaque ID', async ({ page }) => {
  await setup(page, { resolve: 'missing' });
  await page.goto('/ui/#identities/users/u_kim');
  await expect(page.locator('#view-identities h1')).toHaveText('u_kim');
  await expect(page.locator('#view-identities [data-subject-state="unavailable"]')).toContainText('showing the opaque ID');
});

test('subject picker searches Hopae and is keyboard operable', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#access/decisions');
  const view = page.locator('#view-access');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  const input = view.locator('input[name="subject"][role="combobox"]');
  await input.fill('kim');
  await expect(view.locator('.kit-picker [role="option"]')).toHaveCount(2);
  await expect(view.locator('.kit-picker [role="option"]').nth(1)).toContainText('Disabled');
  expect(JSON.parse(calls.find(c => c.path === '/v1/plugins/hopae/subjects/search').body)).toEqual({ q: 'kim', kind: 'human', limit: 10, cursor: null, privacy_profile: 'standard' });
  await input.press('ArrowDown');
  await expect(input).toHaveAttribute('aria-activedescendant', /-0$/);
  await input.press('Enter');
  await expect(input).toHaveValue('u_kim');
  await expect(input).toHaveAttribute('aria-expanded', 'false');
  await input.press('Enter');
  await expect(page).toHaveURL(/subject=u_kim/);
});

test('raw JSON appears only in System behind a disclosure', async ({ page }) => {
  await setup(page);
  for (const view of ['overview', 'access', 'audit']) {
    await page.locator(`[data-view="${view}"]`).click();
    await expect(page.locator(`#view-${view} .zt-title`)).toBeVisible();
    await expect(page.locator(`#view-${view} pre`)).toHaveCount(0);
  }
  await page.locator('[data-view="system"]').click();
  const raw = page.locator('#view-system details.zt-raw');
  await expect(raw.locator('pre')).toBeHidden();
  await raw.locator('summary').click();
  await expect(raw.locator('pre')).toContainText('"profile": "strict"');
  await expect(page.locator('#view-system')).toContainText('Allow ring full 3');
});

test('390 px dark layout turns tables into cards without horizontal scroll', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await page.goto('/ui/#access/decisions');
  const view = page.locator('#view-access');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  expect(await view.locator('.kit-table thead').evaluate(node => node.getBoundingClientRect().width)).toBeLessThanOrEqual(1);
  await expect(view.locator('tbody td').first()).toHaveCSS('display', 'grid');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await shot(page, 'decision-log-390-dark');
});

test('filters and pagination are keyboard operable', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#access/decisions');
  const view = page.locator('#view-access');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  await view.getByLabel('Outcome').focus();
  await page.keyboard.press('ArrowDown');
  await view.getByLabel('Reason code').focus();
  await page.keyboard.type('hopae.unavailable');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/reason=hopae.unavailable/);
  await view.getByRole('button', { name: 'Next', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await view.locator('tbody a').first().focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#access\/requests\//);
});

test('confirm dialog requires the typed target and a reason', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#overview');
  await expect(page.locator('#view-overview .zt-title')).toBeVisible();
  const result = page.evaluate(async () => {
    const { confirmDialog } = await import('/ui/kit/ui.js');
    const { t } = await import('/ui/zt/shell.js');
    return confirmDialog(t, { title: 'ui.confirm.action', effect: 'ui.confirm.type_target', target: 'reports' });
  });
  const dialog = page.locator('dialog.kit-dialog');
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole('button', { name: 'Confirm' });
  await expect(confirm).toBeDisabled();
  await dialog.locator('input').fill('report');
  await dialog.locator('textarea').fill('grant analysts');
  await expect(confirm).toBeDisabled();
  await dialog.locator('input').fill('reports');
  await expect(confirm).toBeEnabled();
  await confirm.click();
  expect(await result).toEqual({ reason: 'grant analysts' });
});

test('network and service entity routes show recent decisions', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/ip/198.51.100.7');
  await expect(page.locator('#view-network')).toContainText('KR');
  await expect(page.locator('#view-network tbody tr')).toHaveCount(4);
  expect(calls.filter(c => c.path === '/v1/observability/decisions').at(-1).query).toContain('ip=198.51.100.7');
  await page.goto('/ui/#workloads');
  await expect(page.locator('#view-workloads')).toContainText('not configured yet');
});

test('#audit is the unified audit; old #audit-trail links redirect and account audit stays reachable', async ({ page }) => {
  await setup(page);
  await page.evaluate(() => { location.hash = '#audit-trail?source=pumgye'; });
  await expect(page).toHaveURL(/#audit\?source=pumgye$/);
  await expect(page.locator('#view-audit tbody tr')).toHaveCount(1);
  await page.locator('#view-audit').getByRole('link', { name: 'Account audit retention and policy' }).click();
  await expect(page).toHaveURL(/#account-audit$/);
  await expect(page.locator('#view-account-audit')).toBeVisible();
});

test('decision rows are dense, open request detail on click and support column choice', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#access/decisions');
  const view = page.locator('#view-access');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  const height = await view.locator('tbody tr').first().evaluate(row => row.getBoundingClientRect().height);
  expect(height).toBeLessThanOrEqual(48);
  await expect(view.locator('thead th')).not.toContainText(['Revisions']);
  await view.locator('.kit-columns summary').click();
  await view.locator('.kit-columns-list label', { hasText: 'Revisions' }).locator('input').check();
  await expect(view.locator('thead th', { hasText: 'Revisions' })).toBeVisible();
  await expect(view.locator('tbody td.kit-col-time time').first()).toHaveAttribute('title', /2026/);
  await view.locator('tbody tr').nth(1).locator('td.kit-col-reason').click();
  await expect(page).toHaveURL(/#access\/requests\/hg-0000000000000001$/);
});

test('suppressed summaries are a footnote, not a top reason, and changes are one line', async ({ page }) => {
  await setup(page);
  await page.locator('[data-view="overview"]').click();
  const view = page.locator('#view-overview');
  await expect(view.locator('.zt-footnote')).toContainText('410 repeated refusals');
  await expect(view.locator('.zt-top')).not.toContainText(['summarized']);
  const row = view.locator('.zt-changes a').first();
  await expect(row).toBeVisible();
  const box = await row.evaluate(node => node.getBoundingClientRect().height);
  expect(box).toBeLessThanOrEqual(40);
});

test('Hopae admin events join the unified audit with summaries', async ({ page }) => {
  await setup(page, { hopaeEvents: true });
  await page.goto('/ui/#audit?source=hopae');
  const view = page.locator('#view-audit');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('tbody tr').first()).toContainText('Refused an administrative request');
  await expect(view.locator('tbody tr').nth(1)).toContainText('Disabled user u_kim; 3 sessions ended');
  await expect(view.locator('tbody tr').nth(1).getByRole('link', { name: 'u_kim' })).toHaveAttribute('href', '#identities/users/u_kim');
  await expect(view.locator('.zt-sources li', { hasText: 'Hopae administration' }).locator('[data-status="healthy"]')).toBeVisible();
  await expect(view.locator('.zt-sources li', { hasText: 'Sumunjang policy' })).toContainText('Not yet connected');
});

test('request detail actions are real disabled buttons with an explanation', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#access/requests/hg-0000000000000000');
  const action = page.locator('#view-access .kit-action-off').first();
  await expect(action.getByRole('button', { name: 'Re-run in simulator' })).toBeDisabled();
  await expect(action.locator('.kit-tip')).toBeHidden();
  await action.focus();
  await expect(action.locator('.kit-tip')).toBeVisible();
  await expect(action.locator('.kit-tip')).toContainText('explain APIs');
});

test('Sumunjang policy audit joins the unified audit through audit/query', async ({ page }) => {
  const calls = await setup(page, { guardAudit: true });
  await page.goto('/ui/#audit?source=sumunjang');
  const view = page.locator('#view-audit');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  expect(JSON.parse(calls.find(c => c.path === '/v1/plugins/guard/audit/query').body)).toEqual({ limit: 200 });
  const first = view.locator('tbody tr').first();
  await expect(first).toContainText('mode observe -> enforce; allow +1: 192.0.2.0/24');
  await expect(first).toContainText('policy.document.replace');
  await expect(first.locator('[data-status="committed"]')).toBeVisible();
  await expect(view.locator('tbody tr').nth(1).locator('[data-status="refused"]')).toBeVisible();
  await expect(view.locator('.zt-sources li', { hasText: 'Sumunjang policy' }).locator('[data-status="healthy"]')).toBeVisible();
  await first.locator('td.kit-col-source').click();
  const detail = view.locator('.kit-expansion');
  await expect(detail).toContainText('Policy revision');
  await expect(detail).toContainText('41 → 42');
  await expect(detail).toContainText('enable enforcement');
  await expect(detail.locator('.kit-chip-full')).toHaveCount(2);
  await expect(detail.locator('.kit-chip-full').first()).toContainText('aa'.repeat(32));
  await page.locator('#locale-select').selectOption('ko');
  await expect(view.locator('.kit-expansion')).toHaveCount(0);
  await view.locator('tbody tr').first().locator('td.kit-col-source').click();
  await expect(view.locator('.kit-expansion')).toContainText('정책 리비전');
});
