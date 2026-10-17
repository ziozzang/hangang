import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Devices & Workloads (ADR 0020 §6) against Hopae console package 0.1.10
// (no workload snapshot route), Pumgye model v2 through the Hangang broker and
// the Kubernetes protection report.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.WORKLOAD_SCREENS || path.join(web, 'test-results', 'workload-screens');
const NOW = Math.floor(Date.now() / 1000);
const WK1 = `wk2:${'a'.repeat(64)}`, WK2 = `wk2:${'b'.repeat(64)}`, WK3 = `wk2:${'c'.repeat(64)}`;
const S1 = `s_${'1'.repeat(48)}`, S2 = `s_${'2'.repeat(48)}`, S3 = `s_${'3'.repeat(48)}`, LEGACY = `s_${'7'.repeat(48)}`;
const SPIFFE1 = 'spiffe://corp.example/ns/payments/sa/api', SPIFFE2 = 'spiffe://corp.example/ns/payments/sa/worker';
const HOPAE_ROUTES = ['status:GET', 'me:GET', 'users/query:POST', 'subjects/resolve:POST', 'subjects/search:POST', 'subjects/lifecycle:POST', 'subjects/lifecycle/snapshot:POST', 'users/get:POST', 'users/bulk-disable:POST'];
const workload = (principal, subject, namespace, sa, spiffe, extra = {}) => ({ principal, subject_ref: subject, spiffe_id: spiffe, cluster: 'prod-1', namespace, service_account: sa, service_account_uid: `${sa}-uid-0001`, service: 'k8s', ...extra });
const CHANGES = [
  { change: 'workload_observed', user_id: null, at: NOW - 86400 * 3, status: 'active', workload: workload(WK2, S2, 'payments', 'worker', SPIFFE2) },
  { change: 'workload_observed', user_id: null, at: NOW - 7200, status: 'active', workload: workload(WK1, S1, 'payments', 'api', SPIFFE1) },
  { change: 'workload_legacy_mapped', user_id: null, at: NOW - 600, status: 'active', workload: { ...workload(WK1, S1, 'payments', 'api', SPIFFE1), legacy_subject_ref: LEGACY } },
  { change: 'workload_retired', user_id: null, at: NOW - 3600, status: 'retired', workload: { ...workload(WK2, S2, 'payments', 'worker', SPIFFE2), cause: 'uid_changed', replacement: WK3 } },
  { change: 'workload_observed', user_id: null, at: NOW - 1800, status: 'active', workload: workload(WK3, S3, 'payments', 'worker', SPIFFE2, { service_account_uid: 'worker-uid-0002' }) },
];
const PROPOSAL = { id: 'rg_00ff00ff00ff00ff', binding: { id: 'bnd_rg_00ff00ff00ff00ff', effect: 'allow', role: 'reader', subjects: [{ kind: 'workload', ref: WK1 }], scope: { services: ['orders'] }, metadata: { source: 'migrated:legacy-pod' } }, evidence: { legacy_binding: 'bnd_orders_pod', legacy_subject: LEGACY, principal: WK1, spiffe_id: SPIFFE1, namespace: 'payments', service_account: 'api' } };
const BINDINGS = [
  { id: 'bnd_orders_api', effect: 'allow', role: 'writer', subjects: [{ kind: 'workload', ref: WK1 }], scope: { services: ['orders', 'reports'] }, conditions: {}, metadata: { reason: 'orders API writes' } },
  { id: 'bnd_payments_name', effect: 'allow', role: 'reader', subjects: [{ kind: 'workload', ref: SPIFFE1 }], scope: { services: 'all' }, conditions: { expires_at: '2027-01-01T00:00:00Z' }, metadata: { reason: 'read everything by name' } },
  { id: 'bnd_orders_pod', effect: 'allow', role: 'reader', subjects: [{ kind: 'workload', ref: LEGACY }], scope: { services: ['orders'] }, conditions: {}, metadata: { reason: 'pre-ADR 0022 grant' } },
  { id: 'bnd_worker_old', effect: 'deny', permissions: 'all', subjects: [{ kind: 'workload', ref: WK2 }], scope: { services: 'all' }, conditions: {}, metadata: { reason: 'INC-77' } },
];
const PROTECTION = {
  scope: 'instance', enabled: true,
  report: { require_protection: true, client_address_preserved: false, client_address_message: 'Service edge/hangang is ClusterIP; externalTrafficPolicy Local required', guard_configured: true, guard_enforcing: true,
    counts: { protected: 3, unprotected: 0, withheld: 2, invalid_policies: 1, conflicted_policies: 0 },
    ingresses: [
      { namespace: 'payments', name: 'orders', state: 'protected', published: true, policy: 'orders' },
      { namespace: 'payments', name: 'reports', state: 'protected', published: true, policy: 'payments-default' },
      { namespace: 'shop', name: 'storefront', state: 'protected', published: true, policy: 'storefront' },
      { namespace: 'shop', name: 'admin', state: 'withheld', published: false, policy: 'shop-admin', reason: 'ClientAddressUnavailable', message: 'enforcement Required needs a preserving client_address mode' },
      { namespace: 'labs', name: 'beta', state: 'withheld', published: false, reason: 'ProtectionRequired', message: 'no ProtectionPolicy targets this Ingress' },
    ],
    policies: [
      { namespace: 'payments', name: 'orders', accepted: true, reason: 'Accepted' },
      { namespace: 'payments', name: 'payments-default', accepted: true, reason: 'Accepted' },
      { namespace: 'shop', name: 'shop-admin', accepted: true, reason: 'Accepted' },
      { namespace: 'shop', name: 'storefront', accepted: true, reason: 'Accepted' },
      { namespace: 'labs', name: 'broken', accepted: false, reason: 'Invalid' },
    ], truncated: 0 },
  freshness: { snapshot_age_seconds: 42, max_snapshot_staleness_seconds: 300, protected_fail_closed: false, stale_refusals: 0 },
};
function decision(index) {
  return { schema: 'hangang.decision.v1', event_id: `01JB0000000000000000000${index}`, kind: 'enforced', request_id: `hg-${String(index).padStart(16, '0')}`, time: new Date((NOW - index * 60) * 1000).toISOString(),
    route: { route_id: 'orders', host: 'orders.example.test', path_template: '/v1/orders', method: 'POST', service: 'orders' },
    outcome: { result: 'allow', status: 200, deciding_stage: 'enforcement', reason: 'hangang.allowed' },
    stages: [{ stage: 'identity', authority: 'hopae', verdict: 'authenticated', subject_ref: 'sub~WK1PSEUDONYM0001', principal: 'workload', aal: 0 }, { stage: 'enforcement', authority: 'hangang', action: 'forwarded', obligations: [], fence: 'ok', revision: 270 }],
    revisions: { hangang: 270 }, sampling: { class: 'allow', rate: 1 }, privacy: { profile: 'standard', key_epoch: '2026-10-17' } };
}

async function setup(page, { hopae = true, snapshot = false, pumgye = true, protection = PROTECTION, conflict = false } = {}) {
  const calls = [];
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    calls.push({ path: p, method: request.method(), body, query: url.search, reason: request.headers()['x-hangang-change-reason'] || null });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/auth/me') return route.fulfill({ json: { user: { id: 7, username: 'operator', role: 'admin', enabled: true } } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 270, http_routes: 1, tcp_routes: 0, metrics: {}, uptime_seconds: 1, state: {} } });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: hopae ? [{ id: 'hopae', name: 'Hopae', version: '0.1.10', entry: '/ui/plugins/hopae/index.js', api_base: '/v1/plugins/hopae', authentication: 'hangang',
      routes: [...HOPAE_ROUTES, ...(snapshot ? ['subjects/workloads/snapshot:POST'] : [])].map(entry => { const [path_, method] = entry.split(':'); return { path: path_, method, mutation: false }; }) }] : [] } });
    if (p === '/v1/plugins/hopae/subjects/lifecycle') return route.fulfill({ json: { changes: body.include_workloads ? CHANGES : [], next_cursor: 'f1.1.5.e_x', more: false } });
    if (p === '/v1/plugins/hopae/subjects/workloads/snapshot') return route.fulfill({ json: { items: [{ ...workload(WK1, S1, 'payments', 'api', SPIFFE1), status: 'active', first_seen_at: NOW - 86400, last_seen_at: NOW - 60, retired_at: null, cause: null, replacement: null, legacy_subject_refs: [LEGACY] }], next_cursor: null, watermark: 'f1.1.5.e_x' } });
    if (p.startsWith('/v1/plugins/hopae/')) return route.fulfill({ json: {} });
    if (p === '/v1/pumgye/v2/workloads') return pumgye ? route.fulfill({ json: { principals: [
      { ...workload(WK1, S1, 'payments', 'api', SPIFFE1), status: 'active' }, { ...workload(WK2, S2, 'payments', 'worker', SPIFFE2), status: 'retired', cause: 'uid_changed', replacement: WK3 }, { ...workload(WK3, S3, 'payments', 'worker', SPIFFE2), status: 'active' }],
      legacy_mappings: { [LEGACY]: WK1 }, regrant_proposals: [PROPOSAL] } }) : route.fulfill({ status: 503, json: { title: 'Authority Unavailable', detail: 'independent Pumgye authority is not available' } });
    if (p === '/v1/pumgye/v2/policy') return pumgye ? route.fulfill({ json: { revision: 41, policy: { version: 2, bindings: BINDINGS } } }) : route.fulfill({ status: 503, json: { detail: 'independent Pumgye authority is not available' } });
    if (p === '/v1/pumgye/v2/workloads/regrants/apply') return conflict ? route.fulfill({ status: 409, json: { error: { code: 'pumgye.error.revision_conflict', message_key: 'pumgye.error.revision_conflict', current_revision: 42 } } }) : route.fulfill({ json: { revision: 42, applied: body.proposals.length, warnings: [], orphaned: [] } });
    if (p === '/v1/kubernetes/protection') return protection ? route.fulfill({ json: protection }) : route.fulfill({ status: 404, json: { title: 'Not Found', detail: 'not found' } });
    if (p === '/v1/observability/decisions') return route.fulfill({ json: { state: 'enabled', profile: 'standard', items: [decision(1), decision(2)], next_cursor: null } });
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
  await page.waitForTimeout(150);
  await page.screenshot({ path: path.join(shots, `workloads-${name}.png`), fullPage: true });
}

async function expectNoSnakeCase(view) {
  const text = await view.evaluate(root => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const out = [];
    while (walker.nextNode()) {
      const node = walker.currentNode, parent = node.parentElement;
      if (!parent || parent.closest('code, .kit-mono, .kit-entity-id, input, textarea, select, option, .kit-tip, [hidden], .kit-columns, .kit-tag') || !parent.getClientRects().length) continue;
      out.push(node.textContent);
    }
    return out.join(' ');
  });
  expect(text).not.toMatch(/\b[a-z]+_[a-z_]+\b/);
}

test('workloads list merges Hopae principals with Pumgye grants and lists the Hopae manifest gap', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#workloads');
  const view = page.locator('#view-workloads');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  const api = view.locator('tbody tr', { hasText: 'payments / api' });
  await expect(api).toContainText(SPIFFE1);
  await expect(api).toContainText('Live');
  await expect(api.locator('td').nth(4)).toHaveText('1');
  await expect(api).toContainText('+1 on Pod-bound subjects');
  await expect(view.locator('tbody tr', { hasText: 'Retired' })).toContainText('ServiceAccount re-created');
  // Hopae 0.1.10 has no snapshot route: the feed is folded and the gap is shown with a tooltip.
  expect(calls.find(call => call.path === '/v1/plugins/hopae/subjects/lifecycle').body).toMatchObject({ include_workloads: true, limit: 200 });
  expect(calls.some(call => call.path.endsWith('/subjects/workloads/snapshot'))).toBe(false);
  await expect(view.locator('.zt-gaps')).toContainText('Hopae manifest gaps');
  await expect(view.locator('.zt-gaps .kit-action-off')).toHaveAttribute('aria-label', /Workload registry snapshot: Not declared by the installed Hopae console package/);
  await expect(view.locator('.zt-gaps button')).toBeDisabled();
  await expect(view).toContainText("Built from Hopae's lifecycle feed");
  await expectNoSnakeCase(view);
  await view.locator('select[name=status]').selectOption('retired');
  await view.getByRole('button', { name: 'Apply' }).click();
  await expect(page).toHaveURL(/status=retired/);
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await view.locator('input[name=q]').fill('nothing-matches');
  await view.getByRole('button', { name: 'Apply' }).click();
  await expect(view).toContainText('No workload matches these filters');
});

test('the registry snapshot is used when Hopae declares it', async ({ page }) => {
  const calls = await setup(page, { snapshot: true });
  await page.goto('/ui/#workloads');
  const view = page.locator('#view-workloads');
  await expect(view.locator('tbody tr', { hasText: 'payments / api' })).toBeVisible();
  expect(calls.some(call => call.path.endsWith('/subjects/workloads/snapshot'))).toBe(true);
  expect(calls.some(call => call.path.endsWith('/subjects/lifecycle'))).toBe(false);
  await expect(view.locator('.zt-gaps')).toHaveCount(0);
});

test('workload detail: identity, grants by match, legacy mappings, decisions and re-grant apply with CAS and reason', async ({ page }) => {
  const calls = await setup(page);
  await page.goto(`/ui/#workloads/w/${encodeURIComponent(WK1)}`);
  const view = page.locator('#view-workloads');
  await expect(view.getByRole('heading', { level: 1 })).toHaveText('payments / api');
  const identity = view.getByRole('region', { name: 'Identity' });
  await expect(identity).toContainText(WK1);
  await expect(identity).toContainText(S1);
  await expect(identity).toContainText('prod-1');
  const grants = view.getByRole('region', { name: 'Pumgye grants (3)' });
  await expect(grants.locator('tbody tr')).toHaveCount(3);
  await expect(grants.locator('tbody tr', { hasText: 'bnd_payments_name' })).toContainText('SPIFFE ID (survives re-creation)');
  await expect(grants.locator('tbody tr', { hasText: 'bnd_orders_pod' })).toContainText('Pod-bound subject (deprecated)');
  await expect(view.getByRole('region', { name: 'Legacy Pod mappings (1)' })).toContainText(LEGACY);
  await expect(view.getByRole('region', { name: 'Recent decisions' }).locator('tbody tr')).toHaveCount(2);
  expect(calls.find(call => call.path === '/v1/observability/decisions').query).toContain(`subject=${S1}`);
  await expectNoSnakeCase(view);
  const regrants = view.getByRole('region', { name: 'Re-grant proposals (1)' });
  await expect(regrants).toContainText('Copy of bnd_orders_pod');
  await regrants.getByRole('button', { name: 'Apply 1 selected' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog).toContainText('only if the document is still at revision 41');
  await expect(dialog.getByRole('button', { name: 'Apply' })).toBeDisabled();
  await dialog.getByLabel('Type 1 to confirm').fill('1');
  await dialog.getByLabel('Approval reference (optional)').fill('CHG-1001');
  await dialog.getByLabel(/Reason/).fill('move orders grant to the ServiceAccount');
  await dialog.getByRole('button', { name: 'Apply' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Applied 1 re-grants; Pumgye revision 42.');
  const apply = calls.find(call => call.path === '/v1/pumgye/v2/workloads/regrants/apply');
  expect(apply.body).toEqual({ base_revision: 41, proposals: ['rg_00ff00ff00ff00ff'], reason: 'move orders grant to the ServiceAccount', approval_ref: 'CHG-1001' });
  expect(decodeURIComponent(apply.reason)).toBe('move orders grant to the ServiceAccount');
});

test('re-grant conflicts are reported and retired principals explain the replacement', async ({ page }) => {
  await setup(page, { conflict: true });
  await page.goto(`/ui/#workloads/w/${encodeURIComponent(WK1)}`);
  const view = page.locator('#view-workloads');
  await view.getByRole('button', { name: 'Apply 1 selected' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel('Type 1 to confirm').fill('1');
  await dialog.getByLabel(/Reason/).fill('migrate');
  await dialog.getByRole('button', { name: 'Apply' }).click();
  await expect(dialog.getByRole('alert')).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await page.goto(`/ui/#workloads/w/${encodeURIComponent(WK2)}`);
  await expect(view.locator('.zt-banner-warn')).toContainText('re-created with a new UID');
  await expect(view.getByRole('region', { name: 'Identity' }).getByRole('link', { name: /wk2:cccc/ })).toHaveAttribute('href', `#workloads/w/${encodeURIComponent(WK3)}`);
  await expect(view.getByRole('region', { name: 'Pumgye grants (1)' })).toContainText('bnd_worker_old');
});

test('without Pumgye and Hopae the list says which owner is missing', async ({ page }) => {
  await setup(page, { hopae: false, pumgye: false });
  await page.goto('/ui/#workloads');
  const view = page.locator('#view-workloads');
  await expect(view).toContainText('The Hopae console package is not installed');
  await expect(view).toContainText('Pumgye workload grants could not be read');
  await expect(view).toContainText('No workload principals yet');
});

test('protected routes: counts, withheld reasons, staleness gauge, client address and policy acceptance', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#workloads/routes');
  const view = page.locator('#view-workloads');
  await expect(view.locator('.zt-banner-warn')).toContainText('2 Ingresses are withheld');
  const ingresses = view.getByRole('region', { name: 'Ingresses' });
  await expect(ingresses.locator('tbody tr')).toHaveCount(5);
  await expect(ingresses.locator('tbody tr').first()).toContainText('Withheld');
  await expect(ingresses).toContainText('Network enforcement needs the real client address');
  await expect(ingresses).toContainText('No ProtectionPolicy applies and protection is required');
  await expect(view.getByRole('region', { name: 'Snapshot freshness' }).locator('meter')).toHaveAttribute('aria-label', 'Snapshot age 42 of 300 seconds');
  await expect(view.getByRole('region', { name: 'Snapshot freshness' })).toContainText('Fresh');
  const gateway = view.getByRole('region', { name: 'Gateway prerequisites' });
  await expect(gateway).toContainText('Not preserved');
  await expect(gateway).toContainText('externalTrafficPolicy Local required');
  await expect(view.getByRole('region', { name: 'ProtectionPolicies' }).locator('tbody tr').first()).toContainText('The policy is invalid');
  await expectNoSnakeCase(view);
  await ingresses.getByRole('link', { name: /^Protected \(/ }).click();
  await expect(page).toHaveURL(/state=protected/);
  await expect(ingresses.locator('tbody tr')).toHaveCount(3);
});

test('protected routes fail closed when the snapshot is stale; disabled and unsupported gateways say so', async ({ page }) => {
  await setup(page, { protection: { ...PROTECTION, freshness: { snapshot_age_seconds: 420, max_snapshot_staleness_seconds: 300, protected_fail_closed: true, stale_refusals: 17 } } });
  await page.goto('/ui/#workloads/routes');
  const view = page.locator('#view-workloads');
  await expect(view.locator('.zt-banner-danger')).toContainText('protected routes answer 503');
  await expect(view.getByRole('region', { name: 'Snapshot freshness' })).toContainText('Failing closed');
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await setup(page, { protection: { scope: 'instance', enabled: false, report: null, freshness: null } });
  await page.goto('/ui/#workloads/routes');
  await expect(view).toContainText('Kubernetes route protection is not configured');
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await setup(page, { protection: null });
  await page.goto('/ui/#workloads/routes');
  await expect(view).toContainText('This gateway does not report Kubernetes route protection');
});

test('devices page states that device posture is not configured', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#workloads/devices');
  const view = page.locator('#view-workloads');
  await expect(view).toContainText('Device posture is not configured');
  await expect(view).toContainText('Nothing here is simulated');
  await expect(view.locator('.zt-subnav [aria-current="page"]')).toHaveText(/Devices/);
});

test('workload pages fit 390 px, work in dark mode and by keyboard', async ({ page }) => {
  await setup(page);
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await page.setViewportSize({ width: 390, height: 844 });
  const view = page.locator('#view-workloads');
  for (const [hash, ready] of [['#workloads', 'tbody tr'], [`#workloads/w/${encodeURIComponent(WK1)}`, '.zt-regrant'], ['#workloads/routes', 'meter'], ['#workloads/devices', '.zt-device-list']]) {
    await page.goto(`/ui/${hash}`);
    await expect(view.locator(ready).first()).toBeVisible();
    const wide = await page.evaluate(() => [...document.querySelectorAll('#view-workloads *')].filter(node => node.getBoundingClientRect().right > 392).slice(-3).map(node => `${node.tagName}.${node.className} ${Math.round(node.getBoundingClientRect().right)}`));
    expect(await page.evaluate(() => document.documentElement.scrollWidth), `${hash} ${wide.join(' | ')}`).toBeLessThanOrEqual(391);
  }
  await shot(page, 'devices-en-dark-390');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/ui/#workloads');
  await view.locator('tbody tr').first().locator('a').first().focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#workloads\/w\/wk2/);
});

test('screens: workloads list, detail and protected routes in Korean (light, 1440)', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await setup(page);
  await page.locator('#locale-select').selectOption('ko');
  const view = page.locator('#view-workloads');
  await page.goto('/ui/#workloads');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expectNoSnakeCase(view);
  await shot(page, 'list-ko-light-1440');
  await page.goto(`/ui/#workloads/w/${encodeURIComponent(WK1)}`);
  await expect(view.getByRole('region', { name: '최근 판단' }).locator('tbody tr')).toHaveCount(2);
  await expectNoSnakeCase(view);
  await shot(page, 'detail-ko-light-1440');
  await page.goto('/ui/#workloads/routes');
  await expect(view.getByRole('region', { name: 'Ingress' }).locator('tbody tr')).toHaveCount(5);
  await expectNoSnakeCase(view);
  await shot(page, 'routes-ko-light-1440');
});
