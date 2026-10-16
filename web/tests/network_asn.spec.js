import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Network ▸ ASN bundle and proposals against a Sumunjang package 0.2.0
// fixture (docs/ASN_PROPOSALS.md; broker contract v2 patterns).
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.NETWORK_SCREENS || path.join(web, 'test-results', 'network-screens');
const NOW = Math.floor(Date.now() / 1000);
const BASE_ROUTES = ['status:GET', 'policy/document:GET', 'policy/document:PUT', 'candidates:GET', 'candidates/approve:POST', 'blocks:GET', 'blocks:POST', 'blocks:DELETE', 'rules:GET', 'explain:POST', 'explain/batch:POST', 'audit/query:POST', 'asn/catalog/query:POST'];
const ASN_ROUTES = ['asn/bundle:GET', 'asn/bundle:PUT', 'asn/bundle/rollback:POST', 'asn/refresh:POST', 'asn/preview:POST', 'asn/proposals:GET', 'asn/proposals:POST'];
const PATTERNS = [{ path: 'asn/proposals/*', method: 'GET', mutation: false, max_depth: 1 }, { path: 'asn/proposals/*', method: 'POST', mutation: true, max_depth: 1 }];

const IMPACT = {
  computed_at: NOW - 120, asn: 64511, decision_revision: 421, mode: 'observe', networks: 3, network_list: ['198.18.0.0/16', '203.0.113.0/24', '203.0.113.128/25'], network_list_truncated: false,
  estimated: { ipv4_addresses: 65920, ipv6_slash64s: 0 },
  tracked: { addresses: 2, eligible: 2, signals: { honeypot: 3, scanner: 8, auth_failure: 3, invalid_request: 0 }, top: [{ ip: '203.0.113.7', score: 64, suspicion: 'high', events: 9 }, { ip: '198.18.4.2', score: 24, suspicion: 'suspicious', events: 5 }] },
  history: { addresses: 2, score: 110, events: 14 },
  preview: { current_mode: { allow_to_deny: 0, already_denied: 1, unchanged_allow: 1 }, enforce: { allow_to_deny: 1, unchanged_allow: 0 }, samples: [{ ip: '203.0.113.7', score: 64, before: 'allow', after: 'allow', enforce_after: 'deny', reason_after: 'sumunjang.deny.block_asn' }, { ip: '198.18.4.2', score: 24, before: 'allow', after: 'allow', enforce_after: 'deny', reason_after: 'sumunjang.deny.block_asn' }] },
  collisions: { allowlist: [{ allow: '203.0.113.200/32', network: '203.0.113.0/24', expires_at: NOW + 86400 }], zones: [{ zone: 'partner.acme', overlapping_prefixes: 1 }], existing_blocks: ['203.0.113.7/32'] },
  warnings: ['observe mode: activation records blocks but does not deny until enforce mode', 'allowlist entries overlap the scope; allowlisted addresses stay allowed', 'network zones overlap the scope; review zone owners'],
  decision_log: { available: false },
};
const actorRef = name => ({ kind: name === 'admin-credential' ? 'credential' : 'delegated', name, issuer: 'hangang', id: 7 });
function proposal(overrides = {}) {
  return { id: 'p-0a1b2c3d4e5f6a7b8c9d', revision: 3, asn: 64511, scope: { kind: 'aggregates', prefixes: [] }, reason: 'scanner and credential-stuffing hosting', expires_at: NOW + 6 * 86400, state: 'pending', created_by: actorRef('operator'), created_at: NOW - 3600,
    required_approvals: 1, approvals: [], rejection: null, withdrawal: null, activation: null, networks: IMPACT.network_list, impact: IMPACT, decision_log: null,
    history: [{ at: NOW - 3600, by: 'operator', action: 'asn.proposal.create', from: 'draft', to: 'draft', reason: 'scanner and credential-stuffing hosting' }, { at: NOW - 1800, by: 'operator', action: 'asn.proposal.submit', from: 'draft', to: 'pending', reason: 'ready for review' }], ...overrides };
}

async function setup(page, { legacy = false, viewer = 'operator', state = 'pending', conflict = false } = {}) {
  const calls = [];
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    calls.push({ path: p, method: request.method(), body, query: url.search, reason: request.headers()['x-hangang-change-reason'] || null });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/auth/me') return route.fulfill({ json: { user: { id: 7, username: viewer, role: 'admin', enabled: true } } });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: [{ id: 'guard', name: 'Sumunjang', version: legacy ? '0.1.7' : '0.2.0', entry: '/ui/plugins/guard/index.js', api_base: '/v1/plugins/guard', authentication: 'hangang',
      routes: [...BASE_ROUTES, ...(legacy ? [] : ASN_ROUTES)].map(entry => { const [path_, method] = entry.split(':'); return { path: path_, method, mutation: method !== 'GET' && !/preview|query|explain/.test(path_) }; }), route_patterns: legacy ? [] : PATTERNS }] } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 270, http_routes: 1, tcp_routes: 0, metrics: {}, uptime_seconds: 1, state: {} } });
    if (p === '/v1/observability/decisions/facets') return route.fulfill({ json: { state: 'enabled', facets: { outcome: [{ value: 'deny', events: 41, estimated_requests: 41 }, { value: 'allow', events: 12, estimated_requests: 1200 }], stage: [{ value: 'network', events: 30 }, { value: 'authorization', events: 11 }], country: [{ value: 'NL', events: 40 }, { value: 'US', events: 13 }] } } });
    const op = p.startsWith('/v1/plugins/guard/') ? p.slice('/v1/plugins/guard/'.length) : null;
    if (op === 'policy/document') return route.fulfill({ json: { revision: 'p12', policy: { mode: 'observe', auto_block: false, window_secs: 60, threshold: 10, block_ttl_secs: 900, allow: [], weights: { honeypot: 10, scanner: 5, auth_failure: 1, invalid_request: 2 } } } });
    if (op === 'candidates') return route.fulfill({ json: [{ ip: '203.0.113.7', score: 64, suspicion: 'high', eligible: true, events: 9, first_seen: NOW - 3000, last_seen: NOW - 40, asn: 64511 }] });
    if (op === 'blocks') return route.fulfill({ json: [] });
    if (op === 'rules') return route.fulfill({ json: { version: 1, rules: [] } });
    if (op === 'asn/catalog/query') return route.fulfill({ json: { schema: 'sumunjang.asn_catalog.v1', source: 'bundle', total_prefixes: 3, total_asns: 1, entries: [{ asn: 64511, prefixes: ['198.18.0.0/15', '203.0.113.0/24', '2001:db8::/32'] }], next_cursor: null } });
    if (op === 'asn/bundle' && request.method() === 'GET') return route.fulfill({ json: { schema: 'sumunjang.asn_bundle.v1', key_configured: true,
      fetch: { url_configured: true, interval_secs: 3600, status: { last_attempt: NOW - 900, last_success: NOW - 900, last_error: null, last_version: 42, attempts: 18, failures: 1 } },
      current: { version: 42, installed_at: NOW - 900, sha256: 'ab'.repeat(32), state: 'current', source: 'licensed-provider-2026-10', created_at: NOW - 86400, provenance: { dataset: 'routeviews-2026-10-15', generator: 'asn-bundler 1.4' }, prefixes: 98213 },
      history: [{ version: 41, installed_at: NOW - 86400 * 2, sha256: 'cd'.repeat(32), state: 'previous', source: 'licensed-provider-2026-09', created_at: NOW - 86400 * 3, provenance: {}, prefixes: 98001 }] } });
    if (op === 'asn/bundle' || op === 'asn/bundle/rollback' || op === 'asn/refresh') return route.fulfill({ json: { changed: true, version: op === 'asn/bundle/rollback' ? 41 : 43, previous_version: 42, source: 'licensed-provider-2026-10', sha256: 'ef'.repeat(32), audit_id: 'a1',
      diff: { prefixes_before: 98213, prefixes_after: 98220, added: 9, removed: 2, reassigned: 1, samples: { added: [{ network: '192.0.2.0/24', asn: 64500 }], removed: [{ network: '198.51.100.0/24', asn: 64496 }], reassigned: [{ network: '203.0.113.0/24', from: 64500, to: 64511 }] }, top_asns: [{ asn: 64511, added: 5, removed: 0 }] } }, headers: { 'x-hangang-plugin-operation': '97' } });
    if (op === 'asn/preview') return body.scope?.prefixes?.includes('10.0.0.0/8') ? route.fulfill({ status: 400, json: { error: 'invalid ASN proposal', errors: [{ path: '/scope/prefixes/0', message: 'not inside the ASN' }] } }) : route.fulfill({ json: { schema: 'sumunjang.asn_preview.v1', stored: false, impact: IMPACT } });
    if (op === 'asn/proposals' && request.method() === 'GET') return route.fulfill({ json: { schema: 'sumunjang.asn_proposals.v1', required_approvals: 1, proposals: [
      { id: 'p-0a1b2c3d4e5f6a7b8c9d', revision: 3, asn: 64511, scope: 'aggregates', state, reason: 'scanner and credential-stuffing hosting', created_by: 'operator', created_at: NOW - 3600, expires_at: NOW + 6 * 86400, networks: 3, approvals: 0, required_approvals: 1, tracked_addresses: 2 },
      { id: 'p-ffeeddccbbaa99887766', revision: 7, asn: 64500, scope: 'prefixes', state: 'active', reason: 'botnet C2', created_by: 'kim', created_at: NOW - 86400, expires_at: NOW + 86400, networks: 1, approvals: 1, required_approvals: 1, tracked_addresses: 1 },
      { id: 'p-00112233445566778899', revision: 4, asn: 64496, scope: 'asn', state: 'rejected', reason: 'too broad', created_by: 'lee', created_at: NOW - 86400 * 4, expires_at: NOW + 86400 * 3, networks: 40, approvals: 0, required_approvals: 1, tracked_addresses: 0 }] } });
    if (op === 'asn/proposals') return route.fulfill({ json: { proposal: proposal({ id: 'p-new0000000000000000a', state: 'draft', revision: 1, history: [] }) }, headers: { 'x-hangang-plugin-operation': '98' } });
    if (op?.startsWith('asn/proposals/') && request.method() === 'GET') return route.fulfill({ json: proposal({ id: op.split('/').pop(), state }) });
    if (op?.startsWith('asn/proposals/')) {
      if (conflict && body.action !== 'annotate') return route.fulfill({ status: 409, json: { error: 'proposal revision conflict; reload and retry', current_revision: 5 } });
      const next = proposal({ id: op.split('/').pop(), state, revision: 4, decision_log: body.action === 'annotate' ? { counts: body.decision_log, attached_by: viewer, attached_at: NOW } : null });
      return route.fulfill({ json: next, headers: { 'x-hangang-plugin-operation': '99' } });
    }
    if (op === 'explain/batch') return route.fulfill({ json: { results: [] } });
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
  await page.screenshot({ path: path.join(shots, `network-${name}.png`), fullPage: true });
}

async function expectNoSnakeCase(view) {
  const text = await view.evaluate(root => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const out = [];
    while (walker.nextNode()) {
      const node = walker.currentNode, parent = node.parentElement;
      if (!parent || parent.closest('code, .kit-mono, .kit-entity-id, input, textarea, select, option, .kit-tip, [hidden], .kit-columns, .zt-provenance, .kit-chip, .zt-zone') || !parent.getClientRects().length) continue;
      out.push(node.textContent);
    }
    return out.join(' ');
  });
  expect(text).not.toMatch(/\b[a-z]+_[a-z_]+\b/);
}

test('bundle status shows version, provenance, signature key, refresh and rollback with CAS and reason', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/asn/bundle');
  const view = page.locator('#view-network');
  await expect(view.locator('.zt-tabs [aria-current="page"]')).toHaveText('Prefix bundle');
  const current = view.getByRole('region', { name: 'Installed bundle' });
  await expect(current).toContainText('v42');
  await expect(current).toContainText('licensed-provider-2026-10');
  await expect(current).toContainText('98,213');
  await expect(current).toContainText('Trusted key configured');
  await expect(current).toContainText('routeviews-2026-10-15');
  await expect(view.getByRole('region', { name: 'Scheduled refresh' })).toContainText('18 attempts, 1 failures');
  await expectNoSnakeCase(view);
  await shot(page, 'asn-bundle-en-light-1440');
  await view.getByRole('button', { name: 'Refresh now' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel(/Reason/).fill('provider published October data');
  await dialog.getByRole('button', { name: 'Refresh now' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Bundle v43 installed (operation 97)');
  await expect(view.locator('.zt-diff-report')).toContainText('Reassigned');
  await expect(view.locator('.zt-diff-report')).toContainText('AS64500 → AS64511');
  await view.getByRole('button', { name: 'Roll back' }).click();
  await dialog.getByLabel('Type v42 to confirm').fill('v42');
  await dialog.getByLabel(/Reason/).fill('bad provider data');
  await dialog.getByRole('button', { name: 'Roll back' }).click();
  expect(calls.filter(call => call.path.endsWith('/asn/bundle/rollback')).at(-1).body).toEqual({ expected_version: 42, reason: 'bad provider data' });
  // Upload: files over 1 MiB are refused before sending.
  await view.getByRole('button', { name: 'Upload bundle' }).click();
  await dialog.locator('input[type=file]').setInputFiles({ name: 'big.json', mimeType: 'application/json', buffer: Buffer.alloc(1024 * 1024 + 1, 32) });
  await expect(dialog).toContainText('larger than 1 MiB');
  await dialog.locator('input[type=file]').setInputFiles({ name: 'bundle.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ payload: 'eyJ…', signature: 'c2ln' })) });
  await expect(dialog).toContainText('bundle.json');
  await dialog.getByLabel(/Reason/).fill('manual install');
  await dialog.getByRole('button', { name: 'Upload bundle' }).click();
  const put = calls.filter(call => call.path.endsWith('/asn/bundle') && call.method === 'PUT').at(-1);
  expect(put.body).toEqual({ payload: 'eyJ…', signature: 'c2ln' });
  expect(decodeURIComponent(put.reason)).toBe('manual install');
});

test('proposals list filters by state and shows approvals and expiry', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#network/asn/proposals');
  const view = page.locator('#view-network');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expect(view.locator('tbody tr').first()).toContainText('AS64511');
  await expect(view.locator('tbody tr').first()).toContainText('Awaiting approval');
  await expect(view.locator('tbody tr').first()).toContainText('0 of 1');
  await view.locator('.zt-filter-chips a', { hasText: 'Open' }).click();
  await expect(page).toHaveURL(/state=open/);
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expectNoSnakeCase(view);
});

test('proposal wizard: ASN, scope with preview and located errors, reason and expiry, then draft with decision-log counts', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/asn/proposals/new');
  const view = page.locator('#view-network');
  await view.locator('input[name=asn]').fill('64511');
  await view.getByRole('button', { name: 'Next' }).click();
  await view.getByRole('radio', { name: /Selected prefixes/ }).check();
  await expect(view.locator('.zt-prefix-choices input')).toHaveCount(3);
  await view.locator('.zt-prefix-choices label', { hasText: '203.0.113.0/24' }).locator('input').check();
  await view.getByRole('button', { name: 'Preview impact' }).click();
  await expect(view.locator('.zt-impact-view')).toContainText('Allowlist entries overlap the scope');
  expect(calls.filter(call => call.path.endsWith('/asn/preview')).at(-1).body).toEqual({ asn: 64511, scope: { kind: 'prefixes', prefixes: ['203.0.113.0/24'] } });
  await view.getByRole('radio', { name: /Evidence aggregates/ }).check();
  await view.getByLabel('Additional aggregates (optional)').fill('10.0.0.0/8');
  await view.getByRole('button', { name: 'Preview impact' }).click();
  await expect(view.locator('.zt-field-errors')).toContainText('/scope/prefixes/0');
  await view.getByLabel('Additional aggregates (optional)').fill('');
  await view.getByRole('button', { name: 'Preview impact' }).click();
  await expect(view.locator('.zt-impact-view')).toBeVisible();
  await view.getByRole('button', { name: 'Next' }).click();
  await view.locator('textarea[name=reason]').fill('scanner hosting');
  await view.locator('select[name=expires]').selectOption('14');
  await view.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/#network\/asn\/proposals\/p-new0000000000000000a/);
  const created = calls.find(call => call.path.endsWith('/plugins/guard/asn/proposals') && call.method === 'POST').body;
  expect(created).toMatchObject({ asn: 64511, scope: { kind: 'aggregates' }, reason: 'scanner hosting' });
  expect(created.expires_at - NOW).toBeGreaterThan(13 * 86400);
  // Decision-log counts were attached through annotate (counts only, from the console's facets for this ASN).
  const annotate = calls.find(call => call.body?.action === 'annotate');
  expect(annotate.body.decision_log).toMatchObject({ window_hours: 168, events: 53, deny: 41, allow: 12, network_stage: 30, countries: 2 });
  expect(Object.values(annotate.body.decision_log).every(Number.isInteger)).toBe(true);
  expect(calls.find(call => call.path === '/v1/observability/decisions/facets').query).toContain('asn=64511');
});

test('proposal detail: impact, collisions, timeline; two-person rule for the proposer', async ({ page }) => {
  await setup(page, { viewer: 'operator' });
  await page.goto('/ui/#network/asn/proposals/p-0a1b2c3d4e5f6a7b8c9d');
  const view = page.locator('#view-network');
  await expect(view.getByRole('heading', { name: 'Block proposal for AS64511', level: 1 })).toBeVisible();
  await expect(view.locator('.zt-banner').first()).toContainText('cannot approve it');
  await expect(view.getByRole('button', { name: 'Approve' })).toBeDisabled();
  await expect(view.locator('.kit-action-off', { hasText: 'Approve' })).toHaveAttribute('aria-label', /Two-person rule/);
  const impact = view.getByRole('region', { name: 'Impact analysis' });
  await expect(impact).toContainText('65,920');
  await expect(impact).toContainText('Observe mode: activation records blocks');
  await expect(impact.getByRole('region', { name: 'Collisions' })).toContainText('partner.acme');
  await expect(impact.getByRole('region', { name: 'Collisions' })).toContainText('203.0.113.200/32');
  await expect(impact.locator('.zt-impact-samples tbody tr')).toHaveCount(2);
  await expect(impact.getByRole('region', { name: /Hangang decision log/ })).toContainText('Denied');
  await expect(view.getByRole('region', { name: 'Approval timeline' })).toContainText('Submitted for review');
  await expectNoSnakeCase(view);
});

test('another administrator approves; activation needs the typed ASN and a reason; conflicts are reported', async ({ page }) => {
  const calls = await setup(page, { viewer: 'kim' });
  await page.goto('/ui/#network/asn/proposals/p-0a1b2c3d4e5f6a7b8c9d');
  const view = page.locator('#view-network');
  await view.getByRole('button', { name: 'Approve' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel(/Reason/).fill('evidence reviewed');
  await dialog.getByRole('button', { name: 'Approve' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Approved (operation 99)');
  expect(calls.filter(call => call.body?.action === 'approve').at(-1).body).toMatchObject({ action: 'approve', expected_revision: 4, reason: 'evidence reviewed' });
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  const approved = await setup(page, { viewer: 'kim', state: 'approved', conflict: true });
  await page.goto('/ui/#network/asn/proposals/p-0a1b2c3d4e5f6a7b8c9d');
  await expect(view.locator('.zt-banner', { hasText: 'Approved but not active' })).toBeVisible();
  await view.getByRole('button', { name: 'Activate block' }).click();
  await expect(dialog.getByRole('button', { name: 'Activate block' })).toBeDisabled();
  await dialog.getByLabel('Type AS64511 to confirm').fill('AS64511');
  await dialog.getByLabel(/Reason/).fill('approved by two admins');
  await dialog.getByRole('button', { name: 'Activate block' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Someone changed this since you loaded it');
  expect(approved.filter(call => call.body?.action === 'activate').at(-1).body.action).toBe('activate');
});

test('older Sumunjang packages (0.1.x) keep the ASN pools page with the proposal placeholder', async ({ page }) => {
  await setup(page, { legacy: true });
  await page.goto('/ui/#network/asn');
  const view = page.locator('#view-network');
  await expect(view.locator('.zt-tabs a')).toHaveCount(1);
  await expect(view.getByRole('button', { name: 'Propose ASN rule' })).toBeDisabled();
  await page.goto('/ui/#network/asn/proposals');
  await expect(view).toContainText('This Sumunjang package does not offer this operation');
});

test('screens: ASN bundle, proposals and proposal impact in Korean (light, 1440)', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await setup(page, { viewer: 'kim' });
  await page.locator('#locale-select').selectOption('ko');
  const view = page.locator('#view-network');
  await page.goto('/ui/#network/asn/bundle');
  await expect(view.getByRole('region', { name: '설치된 번들' })).toContainText('v42');
  await expectNoSnakeCase(view);
  await shot(page, 'asn-bundle-ko-light-1440');
  await page.goto('/ui/#network/asn/proposals');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expectNoSnakeCase(view);
  await shot(page, 'asn-proposals-ko-light-1440');
  await page.goto('/ui/#network/asn/proposals/p-0a1b2c3d4e5f6a7b8c9d');
  await expect(view.getByRole('region', { name: '영향 분석' })).toContainText('65,920');
  await expectNoSnakeCase(view);
  await shot(page, 'asn-proposal-ko-light-1440');
});

test('ASN pages fit 390 px and render in dark mode', async ({ page }) => {
  await setup(page, { viewer: 'kim' });
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await page.setViewportSize({ width: 390, height: 844 });
  const view = page.locator('#view-network');
  for (const [hash, ready] of [['#network/asn/bundle', '.zt-provenance'], ['#network/asn/proposals', 'tbody tr'], ['#network/asn/proposals/p-0a1b2c3d4e5f6a7b8c9d', '.zt-impact-samples'], ['#network/asn/proposals/new', 'input[name=asn]']]) {
    await page.goto(`/ui/${hash}`);
    await expect(view.locator(ready).first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
  }
  await shot(page, 'asn-proposal-new-en-dark-390');
});
