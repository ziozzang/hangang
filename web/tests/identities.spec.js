import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Identities section (ADR 0020 §3) against a Hopae console package fixture
// that follows Hopae docs/ADMIN.md, SUBJECT_DIRECTORY.md, GROUPS.md and
// AUTHENTICATION_EXPLAIN.md shapes. Screens go to IDENTITIES_SCREENS when set.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.env.IDENTITIES_SCREENS || path.join(web, 'test-results', 'identities-screens');
const NOW = Math.floor(Date.UTC(2026, 9, 16, 9, 0) / 1000);
const ROUTES = ['status:GET', 'authentication/profiles:GET', 'authentication/profiles/publish:POST', 'authentication/projections:GET', 'authentication/projections/publish:POST', 'users/query:POST', 'sessions/query:POST', 'events/query:POST', 'users/disable:POST', 'users/enable:POST', 'users/sessions-terminate:POST', 'sessions/terminate:POST', 'subjects/resolve:POST', 'subjects/search:POST', 'explain/authentication:POST', 'groups/search:POST', 'groups/get:POST', 'subjects/groups:POST', 'groups/create:POST', 'groups/update:POST', 'groups/delete:POST', 'groups/members/add:POST', 'groups/members/remove:POST'];

const blank = { reason: null, kind: 'human', human_subject: null, display_name: null, email: null, providers: [], created_at: null, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null };
const PEOPLE = {
  u_kim: { ...blank, id: 'u_kim', user_id: 'u_kim', status: 'active', display_name: 'Kim Analyst', email: 'k***@corp.example', providers: ['corp'], human_subject: 'human1:' + '7a'.repeat(32), created_at: NOW - 86400 * 90, last_login_at: NOW - 3600, last_seen_at: NOW - 120 },
  u_lee: { ...blank, id: 'u_lee', user_id: 'u_lee', status: 'active', display_name: 'Lee Operator', email: 'l***@corp.example', providers: ['corp', 'directory'], created_at: NOW - 86400 * 40, last_login_at: NOW - 7200, last_seen_at: NOW - 900 },
  u_park: { ...blank, id: 'u_park', user_id: 'u_park', status: 'disabled', display_name: 'Park Former', email: 'p***@corp.example', providers: ['directory'], created_at: NOW - 86400 * 300, last_login_at: NOW - 86400 * 20 },
};
const GROUPS = {
  'grp1:LOCALANALYSTS0000000000000': { group_id: 'grp1:LOCALANALYSTS0000000000000', source: 'local', provider_id: null, key: 'analysts', name: 'Analysts', description: 'Reporting analysts', state: 'active', revision: 4, members: 2, created_at: NOW - 86400 * 30, updated_at: NOW - 3600, last_seen_at: null, deleted_at: null },
  'grp1:LDAPENGINEERING00000000000': { group_id: 'grp1:LDAPENGINEERING00000000000', source: 'ldap', provider_id: 'directory', key: 'cn=engineering,ou=apps,dc=example,dc=test', name: 'engineering', description: '', state: 'active', revision: 9, members: 1, created_at: NOW - 86400 * 60, updated_at: NOW - 86400, last_seen_at: NOW - 600, deleted_at: null },
};
const membership = (extra = {}) => ({ source: 'local', provider_id: null, first_seen_at: NOW - 86400 * 7, last_seen_at: NOW - 86400 * 7, expires_at: null, removal_pending_at: null, added_by: 'operator', reason: 'quarterly access review', ...extra });
const sessions = [
  { session_id: 's_KIM1', user_id: 'u_kim', primary_email: 'kim@corp.example', provider_id: 'corp', aal: 2, factors: ['webauthn'], hosts: ['app.example.test', 'reports.example.test'], created_at: NOW - 3600, last_seen_at: NOW - 120, absolute_expires_at: NOW + 3600 * 11, auth_time: NOW - 3600, auth_time_source: 'hopae_completion', bound_ip: '198.51.100.7', ua_prefix: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Chrome/129.0' },
  { session_id: 's_KIM2', user_id: 'u_kim', primary_email: 'kim@corp.example', provider_id: 'corp', aal: 1, factors: [], hosts: ['app.example.test'], created_at: NOW - 86400, last_seen_at: NOW - 5000, absolute_expires_at: NOW + 3600, auth_time: NOW - 86400, auth_time_source: 'provider_claim', bound_ip: null, ua_prefix: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1' },
  { session_id: 's_LEE1', user_id: 'u_lee', primary_email: 'lee@corp.example', provider_id: 'directory', aal: 1, factors: ['totp'], hosts: ['app.example.test'], created_at: NOW - 7200, last_seen_at: NOW - 900, absolute_expires_at: NOW + 3600 * 4, auth_time: NOW - 7200, auth_time_source: 'hopae_completion', bound_ip: '203.0.113.9', ua_prefix: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0' },
];
const PROFILES = { revision: 3, digest: 'ab'.repeat(32), configuration: { authority_id: 'corp-services', profiles: [
  { service_id: 'reports-api', host: 'api.example.test', ports: [443], realm: 'reports', api_keys: [{ token_env: 'REPORTS_BATCH_TOKEN', subject: 'batch-exporter', expires_at: Date.UTC(2027, 0, 1) }], networks: ['10.0.0.0/8'], session_fallback: false },
  { service_id: 'billing', host: 'billing.example.test', ports: [443, 8443], realm: 'billing', api_keys: [], networks: [], session_fallback: true, api_relay: { url: 'https://verifier.example.test', issuer: 'corp' } },
] } };

async function setup(page, { conflict = false, noHopae = false, partialRoutes = null } = {}) {
  const calls = [];
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    calls.push({ path: p, method: request.method(), body, reason: request.headers()['x-hangang-change-reason'] || null });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: noHopae ? [] : [{ id: 'hopae', name: 'Hopae', version: '0.1.9', authentication: 'hangang', api_base: '/v1/plugins/hopae', routes: (partialRoutes || ROUTES).map(entry => { const [path_, method] = entry.split(':'); return { path: path_, method, mutation: !/query|search|resolve|get|status|groups$|profiles$|projections$|explain/.test(path_) }; }) }] } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 270, http_routes: 1, tcp_routes: 0, metrics: {}, uptime_seconds: 1, state: {} } });
    if (p === '/v1/config') return route.fulfill({ json: { revision: 270, pumgye: { version: 1, information_classes: ['public', 'internal', 'restricted'], services: {
      reports: { permissions: ['read', 'write'], roles: { reader: { permissions: ['read'], information_classes: ['internal'], inherits: [], minimum_aal: 1 }, analyst: { permissions: ['write'], information_classes: ['restricted'], inherits: ['reader'], minimum_aal: 2 } }, users: { u_kim: ['analyst'] }, groups: { 'grp1:LOCALANALYSTS0000000000000': ['reader'] }, networks: [] },
      billing: { permissions: ['read'], roles: { viewer: { permissions: ['read'], information_classes: ['internal'], inherits: [], minimum_aal: 1 } }, users: {}, groups: { 'grp1:LOCALANALYSTS0000000000000': ['viewer'] }, networks: [] } } } } });
    if (p === '/v1/observability/decisions') return route.fulfill({ json: { state: 'enabled', profile: 'standard', items: [], next_cursor: null } });
    const op = p.startsWith('/v1/plugins/hopae/') ? p.slice('/v1/plugins/hopae/'.length) : null;
    if (op === 'users/query') return route.fulfill({ json: { items: Object.values(PEOPLE).map(person => ({ user_id: person.user_id, primary_email: person.email.replace('***', 'x'), email_verified: true, display_name: person.display_name, username: null, status: person.status, created_at: person.created_at, last_login_at: person.last_login_at, live_sessions: sessions.filter(s => s.user_id === person.user_id).length, role: null })), next_cursor: null } });
    if (op === 'subjects/search') return route.fulfill({ json: { items: Object.values(PEOPLE).filter(person => person.display_name.toLowerCase().includes(String(body.q).toLowerCase()) && (!body.status || person.status === body.status)), next_cursor: null, privacy_profile: 'standard' } });
    if (op === 'subjects/resolve') {
      const items = body.ids.map(id => PEOPLE[id] ? { ...PEOPLE[id], ...(body.include_groups ? { groups: id === 'u_kim' ? [{ group_id: 'grp1:LOCALANALYSTS0000000000000', name: 'Analysts', source: 'local' }, { group_id: 'grp1:LDAPENGINEERING00000000000', name: 'engineering', source: 'ldap' }] : [], groups_truncated: false } : {}) } : { ...blank, kind: null, id, status: 'unknown', reason: 'not_found' });
      return route.fulfill({ json: { items, resolved: items.filter(item => item.status !== 'unknown').length, unknown: 0, complete: true, privacy_profile: 'standard' } });
    }
    if (op === 'groups/search') return route.fulfill({ json: { items: Object.values(GROUPS).filter(group => (!body.source || group.source === body.source) && (!body.q || group.name.toLowerCase().includes(body.q.toLowerCase()))), next_cursor: null } });
    if (op === 'groups/get') {
      const group = GROUPS[body.group_id];
      if (!group) return route.fulfill({ status: 404, json: { error: 'group_not_found' } });
      const members = group.source === 'local' ? [{ subject: PEOPLE.u_kim, membership: membership() }, { subject: PEOPLE.u_lee, membership: membership({ expires_at: NOW + 86400 * 30, reason: 'project Atlas' }) }] : [{ subject: PEOPLE.u_lee, membership: membership({ source: 'ldap', provider_id: 'directory', added_by: null, reason: null }) }];
      return route.fulfill({ json: { group, members: body.members_limit === 0 ? [] : members, next_members_cursor: null, privacy_profile: 'standard' } });
    }
    if (op === 'subjects/groups') return route.fulfill({ json: { id: body.id, user_id: body.id, status: 'resolved', items: body.id === 'u_kim' ? [{ ...GROUPS['grp1:LOCALANALYSTS0000000000000'], membership: membership() }, { ...GROUPS['grp1:LDAPENGINEERING00000000000'], membership: membership({ source: 'ldap', provider_id: 'directory' }) }] : [], next_cursor: null } });
    if (op === 'sessions/query') return route.fulfill({ json: { items: sessions, next_cursor: null } });
    if (op === 'events/query') return route.fulfill({ json: { items: [
      { event_id: 'e_3', at: NOW - 600, kind: 'factor.webauthn_used', outcome: 'success', reason: null, user_id: 'u_kim', session_id: 's_KIM1', app_id: 'reports', provider_id: null, client_ip: '198.51.100.7', attrs: {} },
      { event_id: 'e_2', at: NOW - 3600, kind: 'login.succeeded', outcome: 'success', reason: null, user_id: 'u_kim', session_id: 's_KIM1', app_id: null, provider_id: 'corp', client_ip: '198.51.100.7', attrs: {} },
      { event_id: 'e_1', at: NOW - 86400 * 3, kind: 'factor.webauthn_registered', outcome: 'success', reason: null, user_id: 'u_kim', session_id: null, app_id: null, provider_id: null, client_ip: '198.51.100.7', attrs: {} },
      { event_id: 'e_0', at: NOW - 86400 * 3, kind: 'login.failed', outcome: 'failure', reason: 'provider_error', user_id: 'u_lee', attrs: {} }], next_cursor: null } });
    if (op === 'status') return route.fulfill({ json: { providers: [
      { provider_id: 'corp', kind: 'oidc', display_name: 'Corporate SSO', enabled: true, managed_by: 'file', health: 'ok', reauth: 'max_age', client_secret_env: 'CORP_CLIENT_SECRET', secret_present: true },
      { provider_id: 'directory', kind: 'ldap', display_name: 'Directory', enabled: true, managed_by: 'file', health: 'degraded', reason: 'bind timed out after 5s', reauth: 'unsupported', client_secret_env: null, secret_present: false },
      { provider_id: 'partner', kind: 'oidc', display_name: 'Partner login', enabled: false, managed_by: 'api', health: 'disabled', reauth: 'unsupported', client_secret_env: 'PARTNER_SECRET', secret_present: false }],
      authentication_gateway: { revision: 3, available: true, enabled: true, connectors: [{ service_id: 'billing', connector: 'api-relay', circuit: 'open', available_capacity: 0 }, { service_id: 'reports-api', connector: 'kubernetes-tokenreview', circuit: 'closed', available_capacity: 8 }] } } });
    if (op === 'authentication/profiles') return route.fulfill({ json: PROFILES });
    if (op === 'authentication/profiles/publish') return conflict ? route.fulfill({ status: 409, json: { error: 'revision_conflict' } }) : route.fulfill({ json: { ...PROFILES, revision: 4, configuration: body.configuration } });
    if (op === 'authentication/projections') return route.fulfill({ json: { revision: 2, digest: 'cd'.repeat(32), configuration: { revision: 2, plans: [{ service: 'reports-api', audience: 'reports-backend', minimum_aal: 2, resource: 'report', action: 'read', credential: { type: 'identity_header' } }] } } });
    if (op === 'explain/authentication') return route.fulfill({ json: {
      outcome: 'step_up', status_code: 302, reason: { code: 'hopae.step_up_required', message_key: 'hopae.explain.step_up_required', message: 'A step-up rule requires…' },
      application: { app_id: 'reports', display_name: 'Reports', step_up_rules: [{ path_prefix: '/admin', aal: 2 }] }, service_profile: null,
      subject: { input: 'subject', item: PEOPLE[body.subject] || null }, session: null,
      providers: [{ provider_id: 'corp', enabled: true, linked: true }],
      assurance: { current_aal: 1, required_aal: 2, achievable_aal: 2, second_factors: { totp_configured: true, totp_enrolled: false, external: [] } },
      step_up: { matched_rules: [0], deciding_rule: 0, required_aal: 2, verdict: { required: { aal: 2, max_age_seconds: 300 } } },
      freshness: { max_auth_age_seconds: 3600, auth_age_seconds: 120, fresh: true },
      after_login: { basis: 'sign_in', outcome: 'allow', reason: { code: 'hopae.allowed' }, trace: [] },
      trace: [{ check: 'path', result: 'pass', detail: {} }, { check: 'application', result: 'pass', detail: {} }, { check: 'session', result: 'info', reason: { code: 'hopae.login_required' }, detail: {} }, { check: 'step_up', result: 'fail', reason: { code: 'hopae.step_up_required' }, detail: {} }],
      evaluated_at: NOW, config_generation: 41, service_profile_revision: 3, simulated: true } });
    if (op === 'users/disable') return route.fulfill({ json: { changed: true, sessions_terminated: 2 }, headers: { 'x-hangang-plugin-operation': '77' } });
    if (op === 'sessions/terminate') return route.fulfill({ json: { changed: true }, headers: { 'x-hangang-plugin-operation': '78' } });
    if (op === 'groups/members/add') return route.fulfill({ json: { group: { ...GROUPS[body.group_id], revision: 5, members: 3 } }, headers: { 'x-hangang-plugin-operation': '79' } });
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
  await page.screenshot({ path: path.join(shots, `identities-${name}.png`), fullPage: true });
}

/** Visible operator text never shows raw snake_case identifiers (code and IDs aside). */
async function expectNoSnakeCase(view) {
  const text = await view.evaluate(root => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const out = [];
    while (walker.nextNode()) {
      const node = walker.currentNode, parent = node.parentElement;
      if (!parent || parent.closest('code, .kit-mono, .kit-entity-id, input, textarea, select, option, .kit-tip, [hidden], .kit-columns') || !parent.getClientRects().length) continue;
      out.push(node.textContent);
    }
    return out.join(' ');
  });
  expect(text).not.toMatch(/\b[a-z]+_[a-z_]+\b/);
  expect(text).not.toMatch(/[{[]\s*"/);
}

async function setLocale(page, locale) {
  await page.locator('#locale-select').selectOption(locale);
}

async function setTheme(page, theme) {
  await page.evaluate(value => { document.documentElement.dataset.theme = value; }, theme);
}

test('users list searches on the server, keeps filters in the URL and links people', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities');
  const view = page.locator('#view-identities');
  await expect(view.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
  await expect(view.locator('tbody tr')).toHaveCount(3);
  await expect(view.locator('tbody tr').first()).toContainText('Kim Analyst');
  await expect(view.locator('tbody tr').first()).toContainText('Analysts');
  await expect(view.locator('tbody tr').nth(2)).toContainText('Disabled');
  // Provider and multi-factor filters explain the missing Hopae API.
  await expect(view.locator('.zt-field-off select')).toHaveCount(2);
  await expect(view.locator('.zt-field-off select').first()).toBeDisabled();
  await expectNoSnakeCase(view);
  await view.getByRole('searchbox', { name: 'Search' }).fill('lee');
  await view.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page).toHaveURL(/#identities\/users\?q=lee$/);
  await expect(view.locator('tbody tr')).toHaveCount(1);
  expect(calls.filter(call => call.path.endsWith('/subjects/search')).at(-1).body).toMatchObject({ q: 'lee', kind: 'human' });
  await view.locator('select[name=group]').selectOption('grp1:LOCALANALYSTS0000000000000');
  await view.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page).toHaveURL(/group=grp1/);
  await expect(view.locator('.zt-notes')).toContainText('Analysts');
});

test('bulk disable requires the typed count and a reason, then reports each outcome', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities/users');
  const view = page.locator('#view-identities');
  await expect(view.locator('tbody tr')).toHaveCount(3);
  // Disabled people cannot be selected.
  await expect(view.locator('tbody tr').nth(2).locator('input[type=checkbox]')).toBeDisabled();
  await view.getByRole('checkbox', { name: 'Select Kim Analyst' }).check();
  await view.getByRole('checkbox', { name: 'Select Lee Operator' }).check();
  await expect(view.locator('.zt-bulk-count')).toHaveText('2 users selected');
  await view.getByRole('button', { name: 'Disable selected' }).click();
  const dialog = page.locator('dialog.kit-dialog');
  const confirm = dialog.getByRole('button', { name: 'Disable users' });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel('Type 2 users to confirm').fill('2 users');
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel('Reason').fill('left the company — 퇴사');
  await confirm.click();
  await expect(view.locator('.zt-bulk-results')).toContainText('2 disabled, 0 refused, 0 uncertain');
  const disables = calls.filter(call => call.path.endsWith('/users/disable'));
  expect(disables.map(call => call.body.id)).toEqual(['u_kim', 'u_lee']);
  expect(decodeURIComponent(disables[0].reason)).toBe('left the company — 퇴사');
});

test('user detail: authentication shows factor gaps honestly and tests access as the user', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities/users/u_kim/authentication');
  const view = page.locator('#view-identities');
  await expect(view.getByRole('heading', { name: 'Kim Analyst', level: 1 })).toBeVisible();
  await expect(view.locator('.zt-tabs [aria-current="page"]')).toHaveText('Authentication');
  await expect(view.locator('.zt-factor')).toHaveCount(3);
  await expect(view.locator('.zt-factor').first()).toContainText('Not reported');
  await expect(view.getByRole('button', { name: 'Reset factors' })).toBeDisabled();
  await expect(view.locator('.kit-action-off', { hasText: 'Reset factors' })).toHaveAttribute('aria-label', /hopae admin factors reset/);
  await expect(view.locator('.zt-panel', { hasText: 'Assurance seen in live sessions' })).toContainText('AAL 2');
  await expect(view.locator('.zt-panel', { hasText: 'Factor activity' }).locator('tbody tr')).toHaveCount(2);
  await view.getByLabel('URL').fill('https://reports.example.test/admin');
  await view.getByRole('button', { name: 'Run test' }).click();
  await expect(view.locator('.zt-explain-result')).toContainText('Step-up required');
  await expect(view.locator('.zt-explain-result')).toContainText('A step-up rule requires a higher assurance level');
  await expect(view.locator('.zt-explain-result')).toContainText('Required: AAL 2');
  expect(calls.filter(call => call.path.endsWith('/explain/authentication')).at(-1).body).toMatchObject({ url: 'https://reports.example.test/admin', subject: 'u_kim', navigation: 'document' });
  await expectNoSnakeCase(view);
  await shot(page, 'user-authentication-en-light-1440');
  // Arrow keys move between tabs.
  await view.locator('.zt-tabs a[aria-current="page"]').focus();
  await page.keyboard.press('ArrowRight');
  await expect(view.locator('.zt-tabs a[data-tab="sessions"]')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#identities\/users\/u_kim\/sessions$/);
});

test('user sessions: device, address, assurance and terminate with a reason', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities/users/u_kim/sessions');
  const view = page.locator('#view-identities');
  const rows = view.locator('tbody tr');
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText('Chrome · macOS');
  await expect(rows.first()).toContainText('198.51.100.7');
  await expect(rows.first()).toContainText('AAL 2');
  await expect(rows.first()).toContainText('Passkey');
  await expect(rows.nth(1)).toContainText('Not bound');
  await expectNoSnakeCase(view);
  await shot(page, 'user-sessions-en-light-1440');
  await rows.first().getByRole('button', { name: 'End session' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await expect(dialog).toContainText('Kim Analyst');
  await expect(dialog.getByRole('button', { name: 'End session' })).toBeDisabled();
  await dialog.getByLabel(/Reason/).fill('lost laptop');
  await dialog.getByRole('button', { name: 'End session' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Session ended (operation 78)');
  const call = calls.filter(entry => entry.path.endsWith('/sessions/terminate')).at(-1);
  expect(call.body).toEqual({ id: 's_KIM1' });
  expect(call.reason).toBe('lost%20laptop');
});

test('user groups, access and activity tabs cross-link groups, Pumgye grants and events', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#identities/users/u_kim/groups');
  const view = page.locator('#view-identities');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('tbody tr').nth(1)).toContainText('LDAP');
  await expect(view.locator('tbody tr').nth(1)).toContainText('Provider-managed');
  await view.locator('.zt-tabs a[data-tab="access"]').click();
  const access = view.locator('tbody tr');
  await expect(access).toHaveCount(2);
  await expect(access.filter({ hasText: 'reports' })).toContainText('read, write');
  await expect(access.filter({ hasText: 'reports' })).toContainText('reader ← Analysts');
  await expect(view.getByRole('link', { name: 'Check access in simulator' })).toHaveAttribute('href', '#policies/simulate?subject=u_kim');
  await view.locator('.zt-tabs a[data-tab="activity"]').click();
  await expect(view.locator('.zt-panel', { hasText: 'Authentication events' }).locator('tbody tr')).toHaveCount(3);
  await expect(view.locator('.zt-panel', { hasText: 'Authentication events' })).toContainText('Passkey used');
  await expectNoSnakeCase(view);
});

test('local group detail writes with revision and reason; provider groups are read-only', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/ui/#identities/groups');
  const view = page.locator('#view-identities');
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.locator('tbody tr').nth(1)).toContainText('LDAP');
  await view.locator('tbody tr').first().click();
  await expect(page).toHaveURL(/#identities\/groups\/grp1%3ALOCALANALYSTS/);
  await expect(view.getByRole('heading', { name: 'Analysts', level: 1 })).toBeVisible();
  await expect(view.locator('tbody tr')).toHaveCount(2);
  await expect(view.getByRole('button', { name: 'Delete group' })).toBeVisible();
  await expectNoSnakeCase(view);
  await shot(page, 'group-detail-en-light-1440');
  await view.getByRole('button', { name: 'Add member' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel('Person').fill('u_park');
  await dialog.getByLabel(/Reason/).fill('joins reporting');
  await dialog.getByRole('button', { name: 'Add member' }).click();
  await expect(view.locator('.zt-outcome')).toContainText('Member added (operation 79)');
  const add = calls.filter(call => call.path.endsWith('/groups/members/add')).at(-1);
  expect(add.body).toMatchObject({ group_id: 'grp1:LOCALANALYSTS0000000000000', expected_revision: 4, user_id: 'u_park', reason: 'joins reporting' });
  await page.goto('/ui/#identities/groups/grp1%3ALDAPENGINEERING00000000000');
  await expect(view.getByRole('note').first()).toContainText('Synced from the LDAP provider directory');
  await expect(view.getByRole('button', { name: 'Delete group' })).toHaveCount(0);
  await expect(view.getByRole('button', { name: 'Add member' })).toHaveCount(0);
});

test('providers render as cards with health, kind and redirect URI, never raw fields', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#identities/providers');
  const view = page.locator('#view-identities');
  await expect(view.locator('.zt-provider')).toHaveCount(3);
  await expect(view.locator('.zt-provider').first()).toContainText('OpenID Connect');
  await expect(view.locator('.zt-provider').first()).toContainText('/callback/corp');
  await expect(view.locator('.zt-provider').nth(1)).toContainText('Degraded');
  await expect(view.locator('.zt-provider').nth(1)).toContainText('bind timed out after 5s');
  await expect(view.locator('.zt-provider').nth(2)).toContainText('Missing');
  await expectNoSnakeCase(view);
  await shot(page, 'providers-en-light-1440');
});

test('authentication profiles: form edit, structured change list, publish with reason; conflicts keep the draft', async ({ page }) => {
  const calls = await setup(page, { conflict: true });
  await page.goto('/ui/#identities/authentication');
  const view = page.locator('#view-identities');
  await expect(view.locator('.zt-profile')).toHaveCount(2);
  await expect(view.locator('.zt-profile').nth(1)).toContainText('kept unchanged by this editor');
  await expect(view.getByRole('button', { name: 'Review and publish' })).toBeDisabled();
  await view.locator('.zt-profile').first().getByLabel('Ports').fill('443, 9443');
  await expect(view.locator('.zt-change-count')).toHaveText('1 change');
  await expect(view.locator('.zt-changes-list')).toContainText('443 → 443, 9443');
  await expectNoSnakeCase(view);
  await shot(page, 'auth-profiles-en-light-1440');
  await view.getByRole('button', { name: 'Review and publish' }).click();
  const dialog = page.locator('dialog.zt-dialog');
  await dialog.getByLabel('Type corp-services to confirm').fill('corp-services');
  await dialog.getByLabel(/Reason/).fill('open the batch port');
  await dialog.getByRole('button', { name: 'Publish' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Someone changed this since you loaded it');
  const publish = calls.filter(call => call.path.endsWith('/authentication/profiles/publish')).at(-1);
  expect(publish.body.revision).toBe(3);
  expect(publish.body.configuration.profiles[0].ports).toEqual([443, 9443]);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await page.reload();
  await page.waitForTimeout(400);
  if (await page.locator('#login-dialog').isVisible()) {
    await page.getByLabel('Administrator token').fill('fixture-token');
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
  }
  await expect(view.locator('.zt-change-count')).toHaveText('1 change');
  await expect(view.getByRole('status').filter({ hasText: 'unsaved draft was restored' })).toBeVisible();
});

test('access test panel explains the outcome and keeps the test in the URL', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#identities/authentication/test?subject=u_kim&url=https%3A%2F%2Freports.example.test%2Fadmin');
  const view = page.locator('#view-identities');
  await expect(view.locator('.zt-explain-result')).toContainText('Step-up required');
  await expect(view.locator('.zt-explain-result')).toContainText('After a fresh sign-in');
  await view.locator('.zt-trace-box summary').click();
  await expect(view.locator('.zt-trace-step')).toHaveCount(4);
  await expect(view.locator('.zt-trace-step').nth(3)).toContainText('Step-up rules');
  await expectNoSnakeCase(view);
  await shot(page, 'auth-test-en-light-1440');
});

test('credential projections show circuit states per service and the plan editor', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#identities/projections');
  const view = page.locator('#view-identities');
  await expect(view.locator('.zt-service')).toHaveCount(2);
  await expect(view.locator('.zt-service', { hasText: 'billing' }).locator('[data-status="deny"]').first()).toContainText('Open');
  await expect(view.locator('.zt-service', { hasText: 'reports-api' })).toContainText('Closed');
  await expect(view.locator('.zt-plan')).toHaveCount(1);
  await expectNoSnakeCase(view);
  await shot(page, 'projections-en-light-1440');
});

test('without Hopae or with an older package the pages explain what is missing', async ({ page }) => {
  await setup(page, { partialRoutes: ROUTES.filter(route => !route.startsWith('groups') && route !== 'users/disable:POST') });
  await page.goto('/ui/#identities/groups');
  const view = page.locator('#view-identities');
  await expect(view).toContainText('This Hopae package does not offer this operation');
  await page.goto('/ui/#identities/users');
  await expect(view.locator('.kit-action-off', { hasText: 'Disable selected' })).toBeVisible();
  await expect(view.locator('select[name=group]')).toBeDisabled();
});

test('Hopae not installed renders a not-connected state', async ({ page }) => {
  await setup(page, { noHopae: true });
  await page.goto('/ui/#identities/providers');
  await expect(page.locator('#view-identities')).toContainText('Hopae is not connected');
});

test('screens: Korean light, English dark and Korean 390 px', async ({ page }) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await setup(page);
  const view = page.locator('#view-identities');
  const pages = [
    ['users', '#identities/users', () => expect(view.locator('tbody tr')).toHaveCount(3)],
    ['user-authentication', '#identities/users/u_kim/authentication', () => expect(view.locator('.zt-factor')).toHaveCount(3)],
    ['user-sessions', '#identities/users/u_kim/sessions', () => expect(view.locator('tbody tr')).toHaveCount(2)],
    ['group-detail', '#identities/groups/grp1%3ALOCALANALYSTS0000000000000', () => expect(view.locator('tbody tr')).toHaveCount(2)],
    ['providers', '#identities/providers', () => expect(view.locator('.zt-provider')).toHaveCount(3)],
    ['auth-test', '#identities/authentication/test?subject=u_kim&url=https%3A%2F%2Freports.example.test%2Fadmin', () => expect(view.locator('.zt-explain-result')).toBeVisible()],
  ];
  for (const [locale, theme, width, suffix] of [['ko', 'light', 1440, 'ko-light-1440'], ['en', 'dark', 1440, 'en-dark-1440'], ['ko', 'light', 390, 'ko-390']]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await setLocale(page, locale);
    await setTheme(page, theme);
    for (const [name, hash, ready] of pages) {
      await page.goto(`/ui/${hash}`);
      await ready();
      if (locale === 'ko') await expect(view.locator('.zt-subnav')).toContainText('사용자');
      await expectNoSnakeCase(view);
      if (width === 390) expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
      await shot(page, `${name}-${suffix}`);
    }
  }
});
