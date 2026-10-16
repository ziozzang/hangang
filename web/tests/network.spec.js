import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Network section (ADR 0020 §5) against a Sumunjang console package fixture
// following Sumunjang docs/AUDIT_EXPLAIN.md, RULES.md and DESIGN.md shapes.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.NETWORK_SCREENS || path.join(web, 'test-results', 'network-screens');
const NOW = Math.floor(Date.now() / 1000);
const ROUTES = ['kubernetes/authority:GET', 'kubernetes/status:GET', 'kubernetes/evaluate:POST', 'status:GET', 'policy/document:GET', 'policy/document:PUT', 'candidates:GET', 'candidates/approve:POST', 'blocks:GET', 'blocks:POST', 'blocks:DELETE', 'lookup:POST', 'networks/inspect:POST', 'rules:GET', 'rules:PUT', 'rules/lua:PUT', 'rules/validate:POST', 'geoip/reload:POST', 'update/status:GET', 'update/check:POST', 'audit:GET', 'audit/query:POST', 'explain:POST', 'explain/batch:POST', 'reasons:GET', 'zones:GET', 'zones:POST'];

const CANDIDATES = [
  { ip: '203.0.113.7', score: 64, suspicion: 'high', eligible: true, events: 9, first_seen: NOW - 3000, last_seen: NOW - 40, asn: 64511 },
  { ip: '198.51.100.23', score: 24, suspicion: 'suspicious', eligible: true, events: 5, first_seen: NOW - 2000, last_seen: NOW - 300, asn: 64511 },
  { ip: '192.0.2.44', score: 6, suspicion: 'watch', eligible: false, events: 3, first_seen: NOW - 900, last_seen: NOW - 600, asn: 64500 },
  { ip: '2001:db8::9', score: 2, suspicion: 'watch', eligible: false, events: 1, first_seen: NOW - 500, last_seen: NOW - 500, asn: null },
];
const BLOCKS = [
  { network: '203.0.113.7/32', expires_at: NOW + 3 * 60, reason: 'manual candidate approval' },
  { network: '198.18.0.0/15', expires_at: NOW + 86400 * 6, reason: 'benchmark range abuse — 벤치마크 대역 악용' },
  { network: '192.0.2.99/32', expires_at: NOW + 700, reason: 'automatic threshold' },
];
const RULES = { version: 1, rules: [
  { id: 'deny-tor-asn', priority: 50, asns: [64511], action: 'deny', score: 20, description: 'abusive hosting ASN' },
  { id: 'corp-allow', priority: 100, network: '10.20.0.0/16', action: 'allow', score: 0, description: 'corporate VPN egress' },
  { id: 'watch-gb', priority: 10, countries: ['GB'], action: 'observe', score: 5, description: '' },
] };

const ZONES = [
  { id: 'corp', display_name: 'Corporate VPN', owner: 'netops', description: 'VPN egress ranges', prefixes: ['10.20.0.0/16', '203.0.113.0/24'], updated_at: NOW - 3600, updated_by: 'operator' },
  { id: 'partner.acme', display_name: null, owner: null, description: null, prefixes: ['198.51.100.0/25', '2001:db8::/48'], updated_at: NOW - 86400, updated_by: 'admin-credential' },
];
function inPrefix(prefix, ip) {
  const [base, bits] = prefix.split('/');
  if (base.includes(':') !== ip.includes(':')) return false;
  if (ip.includes(':')) return ip.startsWith(base.replace(/::$/, ':'));
  const n = value => value.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
  const size = 2 ** (32 - Number(bits));
  return Math.floor(n(ip) / size) === Math.floor(n(base) / size);
}
function zonesOf(ip) { return ZONES.filter(zone => zone.prefixes.some(prefix => inPrefix(prefix, ip))).map(zone => zone.id); }

function explainFor(ip, { mode = 'observe' } = {}) {
  const blocked = ip === '203.0.113.7';
  const enforce = {
    decision: { action: 'deny', mode: 'enforce' }, verdict: 'deny',
    reason_code: blocked ? 'sumunjang.deny.block_approved' : 'sumunjang.deny.rule', params: blocked ? { rule: null, network: '203.0.113.7/32' } : { rule: 'deny-tor-asn', network: null }, matched_rules: blocked ? ['watch-hosting'] : ['deny-tor-asn'],
    stages: [
      { stage: 'mode', mode: 'enforce', code: 'sumunjang.stage.mode.enforce', params: {} },
      { stage: 'zone', informational: true, zones: zonesOf(ip), zone_revision: 5, code: zonesOf(ip).length ? 'sumunjang.stage.zone.match' : 'sumunjang.stage.zone.none', params: { zones: zonesOf(ip).join(', ') } },
      { stage: 'allowlist', matched: false, network: null, code: 'sumunjang.stage.allowlist.miss', params: { network: null } },
      { stage: 'geo', country: 'NL', asn: 64511, asn_source: 'geoip', simulated: false, required: true, code: 'sumunjang.stage.geo.context', params: { country: 'NL', asn: '64511', source: 'geoip' } },
      blocked
        ? { stage: 'rules', configured: 3, winner: 'watch-hosting', matched: [{ id: 'watch-hosting', action: 'observe', priority: 50, score: 20, winner: true, expires_at: null, description: '' }], expired: [{ id: 'old-deny', action: 'deny', priority: 90, expires_at: NOW - 60, code: 'sumunjang.stage.rule.expired', params: { rule: 'old-deny' } }], code: 'sumunjang.stage.rules.observe_winner', params: { rule: 'watch-hosting' } }
        : { stage: 'rules', configured: 3, winner: 'deny-tor-asn', matched: [{ id: 'deny-tor-asn', action: 'deny', priority: 50, score: 20, winner: true, expires_at: null, description: 'abusive hosting ASN' }], expired: [], code: 'sumunjang.stage.rules.winner', params: { rule: 'deny-tor-asn', action: 'deny', priority: 50 } },
      ...(blocked ? [{ stage: 'blocklist', block: { network: '203.0.113.7/32', reason: 'manual candidate approval', expires_at: NOW + 180, remaining_secs: 180 }, expired: [], code: 'sumunjang.stage.block.match', params: { network: '203.0.113.7/32' } }] : []),
      { stage: 'outcome', deciding_stage: blocked ? 'block' : 'rule', action: 'deny', code: blocked ? 'sumunjang.deny.block_approved' : 'sumunjang.deny.rule', params: blocked ? { rule: null, network: '203.0.113.7/32' } : { rule: 'deny-tor-asn', network: null } },
      { stage: 'score', informational: true, signal_score: 44, observed_signal_score: 44, simulated_signal_score: 0, static_rule_score: 20, scored_rules: ['deny-tor-asn'], total: 64, threshold: 10, suspicion: 'high', code: 'sumunjang.stage.score.high', params: { score: 64, threshold: 10 } },
      { stage: 'auto_block', informational: true, enabled: false, would_trigger: false, projected: null, code: 'sumunjang.stage.auto_block.not_triggered', params: {} },
    ], trace_truncated: false,
  };
  if (mode === 'enforce') return { schema: 'sumunjang.explain.v1', ip, ...enforce, evaluated: { source: 'published', revision: 418, policy_revision: 'p12', mode: 'enforce', stored: false } };
  return { schema: 'sumunjang.explain.v1', ip, decision: { action: 'allow', mode: 'observe' }, verdict: 'observe', reason_code: 'sumunjang.observe.mode', params: {}, matched_rules: [],
    stages: [{ stage: 'mode', mode: 'observe', code: 'sumunjang.stage.mode.observe', params: {} }, { stage: 'outcome', deciding_stage: 'observe', action: 'allow', code: 'sumunjang.observe.mode', params: {} }, ...enforce.stages.filter(stage => stage.informational)],
    enforce_preview: enforce, geoip: { country: 'NL', asn: 64511 }, evaluated: { source: 'published', revision: 418, policy_revision: 'p12', mode: 'observe', stored: false } };
}

async function setup(page, { mode = 'observe', zoneConflict = false, zoneInvalid = false, conflict = false, noGuard = false, routes = ROUTES, state = { mode } } = {}) {
  const calls = [];
  const policy = { get mode() { return state.mode; }, auto_block: false, window_secs: 60, threshold: 10, block_ttl_secs: 900, allow: ['10.20.0.0/16', '192.0.2.10/32'], weights: { honeypot: 10, scanner: 5, auth_failure: 1, invalid_request: 2 } };
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    calls.push({ path: p, method: request.method(), body, reason: request.headers()['x-hangang-change-reason'] || null });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: noGuard ? [] : [{ id: 'guard', name: 'Sumunjang', version: '0.1.5', entry: '/ui/plugins/guard/index.js', api_base: '/v1/plugins/guard', authentication: 'native', routes: routes.map(entry => { const [path_, method] = entry.split(':'); return { path: path_, method, mutation: method !== 'GET' && !/lookup|inspect|validate|explain|query|evaluate/.test(path_) }; }) }] } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 270, http_routes: 1, tcp_routes: 0, metrics: {}, uptime_seconds: 1, state: {} } });
    if (p === '/v1/observability/status') return route.fulfill({ json: { state: 'enabled', profile: 'standard', exporter: { connected: true }, rings: {}, keys: {}, counters: { dropped: {} }, store: { rows: 9 } } });
    if (p === '/v1/observability/decisions') return route.fulfill({ json: { state: 'enabled', profile: 'standard', items: [], next_cursor: null } });
    if (p === '/v1/observability/decisions/facets') return route.fulfill({ json: { state: 'enabled', facets: { country: [{ value: 'NL', events: 41, estimated_requests: 41 }, { value: 'US', events: 12, estimated_requests: 12 }] } } });
    if (p === '/v1/observability/decisions/timeseries') return route.fulfill({ json: { state: 'enabled', bucket_seconds: 3600, points: [1, 2, 3, 4, 5, 6].map(i => ({ start_ms: i, outcome: 'deny', events: [3, 8, 2, 12, 6, 9][i - 1], estimated_requests: [3, 8, 2, 12, 6, 9][i - 1] })) } });
    const op = p.startsWith('/v1/plugins/guard/') ? p.slice('/v1/plugins/guard/'.length) : null;
    if (op === 'policy/document' && request.method() === 'GET') return route.fulfill({ json: { revision: 'p12', policy } });
    if (op === 'policy/document') return conflict ? route.fulfill({ status: 409, json: { error: 'policy revision conflict; draft preserved.' } }) : route.fulfill({ json: { revision: 'p13', policy: body.policy }, headers: { 'x-hangang-plugin-operation': '91' } });
    if (op === 'candidates') return route.fulfill({ json: CANDIDATES });
    if (op === 'blocks' && request.method() === 'GET') return route.fulfill({ json: BLOCKS });
    if (op === 'blocks') return route.fulfill({ json: request.method() === 'DELETE' ? { removed: true } : { ok: true }, headers: { 'x-hangang-plugin-operation': '92' } });
    if (op === 'candidates/approve') return route.fulfill({ json: { network: `${body.ip}/32` }, headers: { 'x-hangang-plugin-operation': '93' } });
    if (op === 'rules' && request.method() === 'GET') return route.fulfill({ json: RULES });
    if (op === 'rules' || op === 'rules/lua') return route.fulfill({ json: body?.rules ? body : RULES, headers: { 'x-hangang-plugin-operation': '94' } });
    if (op === 'rules/validate') return body.script && /error/.test(body.script) ? route.fulfill({ status: 400, json: { error: 'invalid explain request', errors: [{ path: '/script', message: 'syntax error near end' }] } }) : route.fulfill({ json: { valid: true, rules: body.rules || RULES } });
    if (op === 'lookup') return route.fulfill({ json: { ip: body.ip, geoip: { country_code: 'NL', country_name: 'Netherlands', city: 'Amsterdam', accuracy_radius_km: 50, asn: 64511, asn_organization: 'Example Hosting B.V.' }, inspection: { ip: body.ip, asn: 64511, score: 64, signal_score: 44, static_rule_score: 20, suspicion: 'high', matched_rules: ['deny-tor-asn'], decision: { action: 'allow' } } } });
    if (op === 'networks/inspect') return route.fulfill({ json: { network: body.network, score: 30, signal_score: 30, static_rule_score: 0, matched_rules: [], events: 14, unique_ips: 2, max_ip_score: 24, suspicion: 'suspicious' } });
    if (op === 'zones' && request.method() === 'GET') return route.fulfill({ json: { schema: 'sumunjang.zones.v1', revision: 5, limits: { zones: 64, prefixes: 65536 }, zones: ZONES } });
    if (op === 'zones') {
      if (zoneConflict) return route.fulfill({ status: 409, json: { error: 'zone revision conflict; reload', current_revision: 6 } });
      if (zoneInvalid) return route.fulfill({ status: 400, json: { error: 'invalid zone', errors: [{ path: '/zone/id', message: 'zone id must match [A-Za-z0-9_.:-]{1,128}' }, { path: '/zone/prefixes/1', message: 'invalid IP address syntax' }] } });
      return route.fulfill({ json: { schema: 'sumunjang.zones.v1', revision: 6, zone: body.zone || null, zones: ZONES }, headers: { 'x-hangang-plugin-operation': '96' } });
    }
    if (op === 'explain') return route.fulfill({ json: explainFor(body.ip, { mode: state.mode }) });
    if (op === 'explain/batch') {
      const results = body.ips.map(ip => { const deny = ip === '203.0.113.7' || (body.candidate && ip.startsWith('198.51')); return { ip, zones: zonesOf(ip), published: { action: ip === '203.0.113.7' && state.mode === 'enforce' ? 'deny' : 'allow', verdict: state.mode === 'enforce' ? (ip === '203.0.113.7' ? 'deny' : 'allow') : 'observe', reason_code: 'sumunjang.allow.default', rules: [], block: null }, ...(body.candidate ? { candidate: { action: deny ? 'deny' : 'allow', verdict: deny ? 'deny' : 'allow', reason_code: deny ? 'sumunjang.deny.rule' : 'sumunjang.allow.default', rules: deny ? ['deny-tor-asn'] : [], block: null }, changed: deny } : {}) }; });
      const changed = results.filter(entry => entry.changed).length;
      return route.fulfill({ json: { schema: 'sumunjang.explain.batch.v1', at: NOW, evaluated: { published_revision: 418, stored: false }, summary: body.candidate ? { total: results.length, changed, allow_to_deny: changed, deny_to_allow: 0, reason_changed: 0 } : null, results } });
    }
    if (op === 'audit/query') return route.fulfill({ json: { schema: 'sumunjang.audit.v1', entries: [{ id: 'a9', time: NOW - 600, actor: { kind: 'delegated', name: 'operator' }, action: 'candidates.approve', target: '203.0.113.7', result: 'committed', summary: 'block +1' }, { id: 'a8', time: NOW - 7200, actor: { kind: 'credential' }, action: 'rules.replace', target: 'rules', result: 'committed' }], next_cursor: null } });
    if (op === 'status') return route.fulfill({ json: { health: 'ok', stats: { accepted: 1532, dropped_capacity: 0, block_capacity_rejections: 0 }, geoip: { country: { database_type: 'DBIP-Country-Lite', build_epoch: NOW - 86400 * 9, bytes: 7340032 }, asn: null }, rules: { count: 3 }, capacity: { candidates: 4, blocks: 3, max_candidates: 10000, max_blocks: 100000 } } });
    if (op === 'update/status') return route.fulfill({ json: { enabled: false, phase: 'disabled', current_version: '0.4.2' } });
    if (op === 'kubernetes/status') return route.fulfill({ status: 503, json: { error: 'source disabled', state: 'disabled', activated: false } });
    if (op === 'kubernetes/authority') return route.fulfill({ json: { enabled: false } });
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
      if (!parent || parent.closest('code, .kit-mono, .kit-entity-id, input, textarea, select, option, .kit-tip, [hidden], .kit-columns, .zt-raw, a[href*="rules?rule"], .zt-trace-rules, .kit-chip') || !parent.getClientRects().length) continue;
      out.push(node.textContent);
    }
    return out.join(' ');
  });
  expect(text).not.toMatch(/\b[a-z]+_[a-z_]+\b/);
  expect(text).not.toMatch(/[{[]\s*"/);
}

test('overview: observe banner, what enforce would change, KPIs, trend and top lists', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network');
  const view = page.locator('#view-network');
  await expect(view.locator('.zt-mode[data-mode="observe"]')).toContainText('Observe mode');
  await expect(view.locator('.zt-enforce-preview')).toContainText('2 of 4 tracked addresses would be denied');
  const batch = calls.find(call => call.path.endsWith('/explain/batch'));
  expect(batch.body.candidate.policy.mode).toBe('enforce');
  await expect(view.locator('.zt-kpi').first()).toContainText('2');
  await expect(view.locator('.zt-kpi').nth(1)).toContainText('1 manual · 1 approved · 1 automatic');
  await expect(view.locator('.zt-kpi-wide')).toContainText('40 denials');
  expect(calls.find(call => call.path === '/v1/observability/decisions/timeseries')).toBeTruthy();
  await expect(view.locator('.zt-panel', { hasText: 'Top denied countries' })).toContainText('NL');
  await expect(view.locator('.zt-panel', { hasText: 'Top ASNs' })).toContainText('AS64511');
  await expect(view.locator('.zt-panel', { hasText: 'Recent policy changes' })).toContainText('Candidate approved: 203.0.113.7');
  await expectNoSnakeCase(view);
});

test('old Sumunjang page is gone from navigation and redirects to Network', async ({ page }) => {
  await setup(page);
  await expect(page.locator('.sidebar [data-view="plugin-guard"]')).toHaveCount(0);
  await page.goto('/ui/#plugin-guard');
  await expect(page).toHaveURL(/#network$/);
  await expect(page.locator('#view-network .zt-subnav')).toBeVisible();
});

test('threat queue filters in the URL and bulk approval needs typed count and reason', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/threats');
  const view = page.locator('#view-network');
  await expect(view.locator('tbody tr')).toHaveCount(4);
  await expect(view.locator('tbody tr').first()).toContainText('203.0.113.7');
  await expect(view.locator('tbody tr').first()).toContainText('High');
  await expect(view.locator('tbody tr').nth(2).locator('input[type=checkbox]')).toBeDisabled();
  await view.getByRole('checkbox', { name: 'Eligible for approval only' }).check();
  await view.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page).toHaveURL(/#network\/threats\?eligible=1$/);
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await view.getByRole('checkbox', { name: 'Select 203.0.113.7' }).check();
  await view.getByRole('checkbox', { name: 'Select 198.51.100.23' }).check();
  await view.getByRole('button', { name: 'Approve blocks' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog.getByRole('button', { name: 'Approve' })).toBeDisabled();
  await dialog.getByLabel('Type 2 addresses to confirm').fill('2 addresses');
  await dialog.getByLabel(/Reason/).fill('scanner burst from hosting range');
  await dialog.getByRole('button', { name: 'Approve' }).click();
  await expect(view.locator('.zt-bulk-results')).toContainText('2 approved, 0 refused, 0 uncertain');
  const approvals = calls.filter(call => call.path.endsWith('/candidates/approve'));
  expect(approvals.map(call => call.body.ip)).toEqual(['203.0.113.7', '198.51.100.23']);
  expect(decodeURIComponent(approvals[0].reason)).toBe('scanner burst from hosting range');
  await view.locator('tbody tr').first().click();
  await expect(page).toHaveURL(/#network\/ip\/203\.0\.113\.7$/);
});

test('IP detail: GeoIP, risk, block with expiry, explain trace and enforce preview', async ({ page }) => {
  await setup(page, { mode: 'enforce' });
  await page.goto('/ui/#network/ip/203.0.113.7');
  const view = page.locator('#view-network');
  await expect(view.getByRole('heading', { name: '203.0.113.7', level: 1 })).toBeVisible();
  await expect(view.locator('.zt-verdict')).toContainText('Deny');
  await expect(view.locator('.zt-verdict')).toContainText('Denied by approved candidate block 203.0.113.7/32.');
  await expect(view.locator('.zt-panel', { hasText: 'Location and network' })).toContainText('Netherlands (NL)');
  await expect(view.locator('.zt-panel', { hasText: 'Location and network' })).toContainText('Example Hosting B.V.');
  await expect(view.locator('.zt-panel', { hasText: 'Block and allow status' })).toContainText('Approved candidate');
  await expect(view.locator('.zt-expiry').first()).toHaveClass(/is-soon/);
  const stages = view.locator('.zt-guard-trace .kit-stage');
  await expect(stages).toHaveCount(9);
  await expect(view.locator('.zt-guard-trace .is-deciding')).toHaveAttribute('data-stage', 'blocklist');
  await expect(view.locator('.zt-guard-trace [data-stage="rules"]')).toContainText('Winning rule watch-hosting only observes; block evaluation continues.');
  await expect(view.locator('.zt-guard-trace [data-stage="rules"] .is-expired')).toContainText('old-deny');
  // The Risk card and the trace read the same explain evaluation.
  const card = view.locator('.zt-matched-rules');
  await expect(card).toHaveAttribute('data-source', 'explain');
  const traceRules = await view.locator('.zt-guard-trace [data-stage="rules"] .zt-trace-rules a').allTextContents();
  const cardRules = await card.locator('a[data-rule]').evaluateAll(links => links.map(link => link.dataset.rule));
  expect(cardRules).toEqual(traceRules);
  await expect(card.locator('.is-winner')).toHaveText('watch-hosting');
  await expect(card.locator('.is-expired')).toHaveText('old-deny');
  await expect(card).not.toContainText('deny-tor-asn');
  // Empty tables show only the empty state, no orphaned header row.
  const decisions = view.locator('.zt-panel', { hasText: 'Recent decisions' });
  await expect(decisions.locator('.kit-empty')).toBeVisible();
  await expect(decisions.locator('table.kit-table')).toBeHidden();
  await expect(view.locator('.zt-guard-trace [data-stage="blocklist"]')).toContainText('Active block 203.0.113.7/32 covers this address.');
  await expect(view.getByRole('button', { name: 'Remove block' })).toBeVisible();
  await expectNoSnakeCase(view);
});

test('IP detail in observe mode shows what enforcement would decide; block asks for a reason', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/ip/198.51.100.23');
  const view = page.locator('#view-network');
  await expect(view.locator('.zt-verdict')).toContainText('Observe (allowed)');
  await expect(view.locator('.zt-trace-tab')).toHaveCount(2);
  await view.getByRole('tab', { name: 'If enforced' }).click();
  await expect(view.locator('.zt-guard-trace [data-stage="rules"]')).toContainText('deny-tor-asn');
  await view.getByRole('button', { name: 'Block', exact: true }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog).toContainText('Observe mode: the block is recorded');
  await expect(dialog.locator('.zt-impact')).toContainText('Sumunjang evidence in range');
  await dialog.getByLabel('Expires after').selectOption('1h');
  await dialog.getByLabel('Type 198.51.100.23/32 to confirm').fill('198.51.100.23/32');
  await dialog.getByLabel(/Reason/).fill('credential stuffing');
  await dialog.getByRole('button', { name: 'Block', exact: true }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Block added (operation 92)');
  const add = calls.filter(call => call.path.endsWith('/blocks') && call.method === 'POST').at(-1);
  expect(add.body.network).toBe('198.51.100.23/32');
  expect(add.body.reason).toBe('credential stuffing');
  expect(add.body.expires_at - Math.floor(Date.now() / 1000)).toBeGreaterThan(3500);
});

test('blocks and allowlist: origins, expiry, manual add with CIDR validation and impact', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/blocks');
  const view = page.locator('#view-network');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expect(view.locator('tbody tr').first()).toContainText('Approved candidate');
  await view.locator('.zt-filter-chips a', { hasText: 'Automatic' }).click();
  await expect(page).toHaveURL(/kind=automatic/);
  await expect(view.locator('tbody tr')).toHaveCount(1);
  await expectNoSnakeCase(view);
  await view.getByRole('button', { name: 'Add block' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  const input = dialog.getByLabel('Address or CIDR');
  await input.fill('198.51.100.0/33');
  await input.blur();
  await dialog.getByLabel(/Reason/).fill('test');
  await dialog.getByRole('button', { name: 'Block', exact: true }).click();
  await expect(dialog).toBeVisible();
  expect(await input.evaluate(node => node.validity.valid)).toBe(false);
  await input.fill('198.51.100.0/24');
  await input.blur();
  await expect(dialog.locator('.zt-impact')).toContainText('1 tracked address in range');
  await dialog.getByRole('button', { name: 'Block', exact: true }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Block added');
  expect(calls.filter(call => call.path.endsWith('/blocks') && call.method === 'POST').at(-1).body.network).toBe('198.51.100.0/24');
  await page.goto('/ui/#network/blocks/allowlist');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await view.locator('tbody tr').nth(1).getByRole('button', { name: 'Remove from allowlist' }).click();
  await dialog.getByLabel('Type 192.0.2.10/32 to confirm').fill('192.0.2.10/32');
  await dialog.getByLabel(/Reason/).fill('contractor left');
  await dialog.getByRole('button', { name: 'Remove' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Removed from the allowlist');
  const put = calls.filter(call => call.path.endsWith('/policy/document') && call.method === 'PUT').at(-1);
  expect(put.body).toMatchObject({ expected_revision: 'p12', reason: 'contractor left' });
  expect(put.body.policy.allow).toEqual(['10.20.0.0/16']);
});

test('rules: structured edit, validate, diff, what-if and publish guarded by a fresh read', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/rules?rule=deny-tor-asn');
  const view = page.locator('#view-network');
  await expect(view.locator('tr.zt-rule')).toHaveCount(3);
  await expect(view.locator('tr.zt-rule.is-highlighted')).toHaveCount(1);
  await view.locator('tr.zt-rule').nth(2).getByLabel('Action').selectOption('deny');
  await expect(view.locator('.zt-change-count')).toHaveText('1 change');
  await expect(view.locator('.zt-changes-list')).toContainText('Observe → Deny');
  await view.getByRole('button', { name: 'Validate' }).click();
  await expect(view.locator('.zt-validation')).toContainText('Valid: 3 rules compiled.');
  await view.getByRole('button', { name: 'Preview impact' }).click();
  await expect(view.locator('.zt-whatif')).toContainText('Allow → deny');
  await expect(view.locator('.zt-whatif-list li')).toHaveCount(2);
  const batch = calls.filter(call => call.path.endsWith('/explain/batch')).at(-1);
  expect(batch.body.candidate.rules.rules[2].action).toBe('deny');
  await expectNoSnakeCase(view);
  await shot(page, 'rules-en-light-1440');
  await view.getByRole('button', { name: 'Review and publish' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog.locator('.zt-whatif')).toBeVisible();
  await dialog.getByLabel('Type rules to confirm').fill('rules');
  await dialog.getByLabel(/Reason/).fill('deny GB after review');
  await dialog.getByRole('button', { name: 'Publish' }).click();
  await expect(view.locator('.zt-outcome', { hasText: 'Published' })).toContainText('Published 3 rules (operation 94)');
  const put = calls.filter(call => call.path.endsWith('/rules') && call.method === 'PUT').at(-1);
  expect(put.body.rules[2].action).toBe('deny');
  expect(decodeURIComponent(put.reason)).toBe('deny GB after review');
});

test('Lua rules use the host editor and show Sumunjang field errors', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#network/rules/lua');
  const view = page.locator('#view-network');
  await expect(view.locator('.hangang-lua-editor')).toBeVisible();
  await expect(view.locator('.zt-banner')).toContainText('never stores Lua source');
  await view.locator('textarea[name=script]').evaluate(node => { node.value = 'error('; node.dispatchEvent(new Event('input', { bubbles: true })); });
  await view.getByRole('button', { name: 'Validate' }).click();
  await expect(view.locator('.zt-validation')).toContainText('syntax error near end');
  await expect(view.locator('.zt-validation code')).toHaveText('/script');
});

test('policy: switching to enforce shows impact and requires typing the mode; conflicts keep the draft', async ({ page }) => {
  const calls = await setup(page, { conflict: true });
  await page.goto('/ui/#network/policy');
  const view = page.locator('#view-network');
  await view.getByRole('radio', { name: /Enforce mode/ }).check();
  await view.getByRole('spinbutton', { name: /^Threshold/ }).fill('20');
  await expect(view.locator('.zt-change-count')).toHaveText('2 changes');
  await view.getByRole('button', { name: 'Review and publish' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog).toContainText('switches Sumunjang to enforce');
  await dialog.getByLabel('Type Enforce mode to confirm').fill('Enforce mode');
  await dialog.getByLabel(/Reason/).fill('go live after a week of observation');
  await dialog.getByRole('button', { name: 'Publish' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Someone changed this since you loaded it');
  const put = calls.filter(call => call.path.endsWith('/policy/document') && call.method === 'PUT').at(-1);
  expect(put.body).toMatchObject({ expected_revision: 'p12', policy: { mode: 'enforce', threshold: 20 }, reason: 'go live after a week of observation' });
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(view.getByRole('spinbutton', { name: /^Threshold/ })).toHaveValue('20');
});

test('ASN pools are read-only with the proposal workflow disabled and explained', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#network/asn');
  const view = page.locator('#view-network');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('tbody tr').first()).toContainText('AS64511');
  await expect(view.locator('tbody tr').first()).toContainText('deny-tor-asn');
  await expect(view.getByRole('button', { name: 'Propose ASN rule' })).toBeDisabled();
});

test('System shows Sumunjang GeoIP, updates and Kubernetes source without raw JSON by default', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#system');
  const view = page.locator('#view-system');
  await expect(view.locator('.zt-panel', { hasText: 'GeoIP databases (Sumunjang)' })).toContainText('DBIP-Country-Lite');
  await expect(view.locator('.zt-panel', { hasText: 'Sumunjang updates' })).toContainText('Updates disabled');
  await expect(view.getByRole('button', { name: 'Check for updates' })).toBeDisabled();
  await expect(view.locator('.zt-panel', { hasText: 'Kubernetes source' })).toContainText('Not configured');
  await expect(view.locator('.zt-panel', { hasText: 'Kubernetes source' }).locator('pre')).toBeHidden();
});

test('without Sumunjang or with an older package the pages explain what is missing', async ({ page }) => {
  await setup(page, { routes: ROUTES.filter(route => !route.startsWith('explain') && route !== 'rules/validate:POST') });
  await page.goto('/ui/#network/rules');
  const view = page.locator('#view-network');
  await expect(view.locator('.kit-action-off', { hasText: 'Validate' })).toBeVisible();
  await expect(view.locator('.kit-action-off', { hasText: 'Preview impact' })).toBeVisible();
  await page.unrouteAll({ behavior: 'ignoreErrors' });
});

test('Sumunjang not installed renders a not-connected state', async ({ page }) => {
  await setup(page, { noGuard: true });
  await page.goto('/ui/#network/threats');
  await expect(page.locator('#view-network')).toContainText('Sumunjang is not connected');
});

test('screens: Korean light, English dark and Korean 390 px', async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  const state = { mode: 'observe' };
  await setup(page, { state });
  const view = page.locator('#view-network');
  const pages = [
    ['overview', '#network/overview', () => expect(view.locator('.zt-enforce-preview')).toContainText('203.0.113.7')],
    ['threats', '#network/threats', () => expect(view.locator('tbody tr')).toHaveCount(4)],
    ['ip-detail', '#network/ip/203.0.113.7', () => expect(view.locator('.zt-guard-trace .kit-stage').first()).toBeVisible()],
    ['rules', '#network/rules', async () => {
      await expect(view.locator('tr.zt-rule')).toHaveCount(3);
      await view.locator('tr.zt-rule').nth(2).locator('select[name=action]').selectOption('deny');
      await view.locator('.zt-editor-bar button').nth(1).click();
      await expect(view.locator('.zt-whatif')).toBeVisible();
    }],
  ];
  for (const [locale, theme, width, suffix] of [['ko', 'light', 1440, 'ko-light-1440'], ['en', 'dark', 1440, 'en-dark-1440'], ['ko', 'light', 390, 'ko-390']]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.locator('#locale-select').selectOption(locale);
    await page.evaluate(value => { document.documentElement.dataset.theme = value; }, theme);
    for (const [name, hash, ready] of pages) {
      // Overview shows the observe-mode preview; the IP page shows an enforced block.
      state.mode = name === 'overview' ? 'observe' : 'enforce';
      await page.goto(`/ui/${hash}`);
      await ready();
      if (locale === 'ko') await expect(view.locator('.zt-subnav')).toContainText('위협 대기열');
      await expectNoSnakeCase(view);
      if (width === 390) expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
      await shot(page, `${name}-${suffix}`);
    }
    await page.evaluate(() => sessionStorage.clear());
  }
});

test('zones: list, detail with prefixes, create with validation, replace with impact and delete with CAS', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#network/zones');
  const view = page.locator('#view-network');
  await expect(view.locator('.zt-subnav [aria-current="page"]')).toContainText('Zones');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('tbody tr').first()).toContainText('Corporate VPN');
  await expect(view.locator('tbody tr').nth(1)).toContainText('Shared admin credential');
  await expect(view.locator('.zt-authority')).toContainText('2 of 64 zones · 4 of 65,536 prefixes');
  await expectNoSnakeCase(view);
  await shot(page, 'zones-en-light-1440');
  // Create: client-side CIDR check, then Sumunjang's JSON Pointer errors.
  await view.getByRole('button', { name: 'Create zone' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel('Zone ID').fill('office');
  await dialog.getByLabel('Prefixes').fill('192.0.2.0/24\nnot-a-prefix');
  await dialog.getByLabel('Prefixes').blur();
  await expect(dialog.locator('.zt-field-errors')).toContainText('/zone/prefixes/1');
  await dialog.getByLabel('Prefixes').fill('192.0.2.0/24\n198.51.100.23');
  await dialog.getByLabel('Prefixes').blur();
  await expect(dialog.locator('.zt-impact')).toContainText('3 join');
  await dialog.getByLabel(/Reason/).fill('new branch office');
  await dialog.getByRole('button', { name: 'Create zone' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Zone created (operation 96)');
  const created = calls.filter(call => call.path.endsWith('/plugins/guard/zones') && call.method === 'POST').at(-1);
  expect(created.body).toEqual({ expected_revision: 5, zone: { id: 'office', prefixes: ['192.0.2.0/24', '198.51.100.23/32'] }, reason: 'new branch office' });
  await expect(page).toHaveURL(/#network\/zones\/office\?updated=/);
  // Detail, replace and delete.
  await page.goto('/ui/#network/zones/corp');
  await expect(view.getByRole('heading', { name: 'Corporate VPN', level: 1 })).toBeVisible();
  await expect(view.locator('.zt-panel', { hasText: 'Prefixes (2)' }).locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('.zt-panel', { hasText: 'Tracked addresses in this zone' })).toContainText('203.0.113.7');
  await expectNoSnakeCase(view);
  await shot(page, 'zone-detail-en-light-1440');
  await view.getByRole('button', { name: 'Edit' }).click();
  await expect(dialog.getByLabel('Zone ID')).toHaveAttribute('readonly', '');
  await dialog.getByLabel('Prefixes').fill('10.20.0.0/16');
  await dialog.getByLabel('Prefixes').blur();
  await expect(dialog.locator('.zt-impact')).toContainText('1 leaves');
  await dialog.getByLabel(/Reason/).fill('retire the old range');
  await dialog.getByRole('button', { name: 'Save zone' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Zone saved');
  expect(calls.filter(call => call.path.endsWith('/plugins/guard/zones') && call.method === 'POST').at(-1).body).toMatchObject({ expected_revision: 5, zone: { id: 'corp', display_name: 'Corporate VPN', owner: 'netops', prefixes: ['10.20.0.0/16'] }, reason: 'retire the old range' });
  await expect(page).toHaveURL(/updated=/);
  await view.getByRole('button', { name: 'Delete zone' }).click();
  await dialog.getByLabel('Type corp to confirm').fill('corp');
  await dialog.getByLabel(/Reason/).fill('merged into partner');
  await dialog.getByRole('button', { name: 'Delete zone' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Zone deleted');
  expect(calls.filter(call => call.path.endsWith('/plugins/guard/zones') && call.method === 'POST').at(-1).body).toEqual({ expected_revision: 5, remove: 'corp', reason: 'merged into partner' });
});

test('zone writes surface Sumunjang path errors and stale revisions without losing the form', async ({ page }) => {
  await setup(page, { zoneInvalid: true });
  await page.goto('/ui/#network/zones');
  const view = page.locator('#view-network');
  await view.getByRole('button', { name: 'Create zone' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel('Zone ID').fill('office');
  await dialog.getByLabel('Prefixes').fill('192.0.2.0/24');
  await dialog.getByLabel(/Reason/).fill('x');
  await dialog.getByRole('button', { name: 'Create zone' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Sumunjang rejected 2 fields');
  await expect(dialog.locator('.zt-field-errors code').first()).toHaveText('/zone/id');
  await expect(dialog.getByLabel('Zone ID')).toHaveAttribute('aria-invalid', 'true');
  await expect(dialog.getByLabel('Prefixes')).toHaveValue('192.0.2.0/24');
});

test('zone labels appear in the IP trace and the threat queue', async ({ page }) => {
  await setup(page, { mode: 'enforce' });
  await page.goto('/ui/#network/ip/203.0.113.7');
  const view = page.locator('#view-network');
  await expect(view.getByRole('region', { name: 'Location and network' }).locator('.zt-zone')).toHaveText('corp');
  await expect(view.locator('.zt-guard-trace [data-stage="zone"]')).toContainText('Address is in network zones: corp.');
  await page.goto('/ui/#network/threats');
  await expect(view.locator('tbody tr').first().locator('.zt-zone')).toHaveText('corp');
  await expect(view.locator('tbody tr').nth(1).locator('.zt-zone')).toHaveText('partner.acme');
});

test('screens: zones list and detail in Korean (light, 1440)', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await setup(page);
  await page.locator('#locale-select').selectOption('ko');
  const view = page.locator('#view-network');
  await page.goto('/ui/#network/zones');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('.zt-subnav')).toContainText('네트워크 존');
  await expectNoSnakeCase(view);
  await shot(page, 'zones-ko-light-1440');
  await page.goto('/ui/#network/zones/corp');
  await expect(view.locator('.zt-panel', { hasText: '접두사(2)' }).locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('.zt-panel', { hasText: '이 존의 추적 주소' })).toContainText('203.0.113.7');
  await expectNoSnakeCase(view);
  await shot(page, 'zone-detail-ko-light-1440');
});
