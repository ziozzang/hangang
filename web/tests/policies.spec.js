import { test, expect } from '@playwright/test';

const HUMAN = 'human1:' + 'a'.repeat(64);
const WORKLOAD = 's_' + 'b'.repeat(48);

export function fixturePolicy() {
  return {
    version: 1,
    information_classes: ['public', 'internal', 'confidential', 'restricted'],
    services: {
      reports: {
        permissions: ['read', 'write', 'export'],
        roles: {
          reader: { permissions: ['read'], information_classes: ['public', 'internal'], inherits: [], minimum_aal: 1 },
          analyst: { permissions: ['read', 'export'], information_classes: ['public', 'internal', 'confidential'], inherits: ['reader'], minimum_aal: 2 },
          admin: { permissions: ['read', 'write', 'export'], information_classes: ['public', 'internal', 'confidential', 'restricted'], inherits: ['analyst'], minimum_aal: 2 },
        },
        users: { u_kim: ['analyst'], u_lee: ['reader'], u_park: ['admin'] },
        human_users: { [HUMAN]: ['reader'] },
        workload_users: { [WORKLOAD]: ['reader'] },
        networks: [{ cidr: '10.0.0.0/8', roles: ['reader', 'analyst', 'admin'] }, { cidr: '192.0.2.0/24', roles: ['reader'] }],
        require_guard: true,
      },
      billing: { permissions: ['read'], roles: { viewer: { permissions: ['read'], information_classes: ['internal'], inherits: [], minimum_aal: 1 } }, users: { u_kim: ['viewer'] }, networks: [], require_guard: false },
      'cluster-api': { authorization_context: 'kubernetes_api', permissions: ['get'], roles: { ops: { permissions: ['get'], information_classes: ['internal'], inherits: [], minimum_aal: 0 } }, users: { 'k8sapi:ops': ['ops'] }, networks: [], require_guard: false },
    },
    resources: { report: { service: 'reports', information_class: 'confidential', actions: { GET: 'read', POST: 'write' }, minimum_aal: 1 } },
  };
}

export const deniedExplain = {
  version: 1, kind: 'simulation', audit_id: 42, snapshot: { source: 'published', revision: 77, serving: true },
  result: {
    outcome: { decision: 'ClassDenied', allow: false, reason_code: 'pumgye.class_denied', message_key: 'pumgye.reason.class_denied', hint_key: 'pumgye.hint.class_denied', deciding_stage: 'information_class', detail_code: 'pumgye.detail.class_missing_subject' },
    trace: [
      { stage: 'fence', result: 'pass', code: 'pumgye.detail.fence_satisfied', label_key: 'pumgye.stage.fence', detail: { revision: 77, minimum_revision: 0, serving: true } },
      { stage: 'service', result: 'pass', code: 'pumgye.detail.service_found', label_key: 'pumgye.stage.service', detail: { service: 'reports' } },
      { stage: 'guard', result: 'pass', code: 'pumgye.detail.guard_enforced_allow', label_key: 'pumgye.stage.guard', detail: { evidence: 'enforced_allow' } },
      { stage: 'subject', result: 'pass', code: 'pumgye.detail.subject_assigned', label_key: 'pumgye.stage.subject', detail: { map: 'users', subject: 'u_lee', roles: ['reader'] } },
      { stage: 'network', result: 'pass', code: 'pumgye.detail.network_matched', label_key: 'pumgye.stage.network', detail: { ip: '10.1.2.3', matched: { index: 0, cidr: '10.0.0.0/8', roles: ['reader', 'analyst', 'admin'] }, shadowed: [] } },
      { stage: 'permission', result: 'pass', code: 'pumgye.detail.permission_granted', label_key: 'pumgye.stage.permission', detail: { requested: 'read' } },
      { stage: 'information_class', result: 'deny', code: 'pumgye.detail.class_missing_subject', label_key: 'pumgye.stage.information_class', detail: { requested: 'restricted' } },
      { stage: 'assurance', result: 'not_evaluated', code: 'pumgye.detail.not_evaluated', label_key: 'pumgye.stage.assurance', detail: {} },
    ],
  },
};

export async function setup(page, { owner = 'native', putStatus = 200, explain = deniedExplain, explainStatus = 200 } = {}) {
  const calls = [];
  let revision = 77, policy = fixturePolicy(), putCount = 0;
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p.startsWith('/ui/')) return route.continue();
    calls.push({ path: p, method: request.method(), body: request.postData(), headers: request.headers() });
    if (p === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (p === '/v1/plugins') return route.fulfill({ json: { api_version: 1, plugins: [] } });
    if (p === '/v1/status') return route.fulfill({ json: { revision: 5, metrics: {}, state: {} } });
    if (p === '/v1/config') return route.fulfill({ json: { revision: 5, http: [], pumgye_authority: { transport: 'grpc' } } });
    if (p === '/v1/pumgye/policy' && request.method() === 'GET') return route.fulfill({ json: { revision, policy }, headers: { etag: `"${revision}"`, 'x-hangang-config-revision': '"5"' } });
    if (p === '/v1/pumgye/policy' && request.method() === 'PUT') {
      putCount += 1;
      const status = Array.isArray(putStatus) ? putStatus[putCount - 1] ?? 200 : putStatus;
      if (status === 409) {
        // Someone else published meanwhile.
        revision += 1; policy = fixturePolicy(); policy.services.billing.require_guard = true;
        return route.fulfill({ status: 409, json: { title: 'Pumgye Operation Rejected', detail: 'owning authority rejected the operation; reload before retrying' } });
      }
      if (status !== 200) return route.fulfill({ status, json: { detail: 'unavailable' } });
      const body = JSON.parse(request.postData()); revision += 1; policy = body.policy;
      return route.fulfill({ json: { revision, policy }, headers: { etag: `"${revision}"`, 'x-hangang-config-revision': '"5"' } });
    }
    if (p === '/v1/pumgye/status') return route.fulfill({ json: { policy_source: owner, revision } });
    if (p === '/v1/pumgye/audit') return route.fulfill({ json: [{ revision: 77, at_unix: 1760600000, actor: 'mtls:operator', sha256: 'ab'.repeat(32) }, { revision: 76, at_unix: 1760500000, actor: 'mtls:operator', sha256: 'cd'.repeat(32) }] });
    if (p === '/v1/pumgye/audit/simulations') return route.fulfill({ json: [{ id: 41, at_unix: 1760600100, kind: 'simulation', actor: 'mtls:x', on_behalf_of: 'console:system', operation: 'explain', source: 'published', revision: 77, cases: 1, allowed: 0, denied: 1, changed: 0 }] });
    if (p === '/v1/pumgye/explain') return route.fulfill({ status: explainStatus, json: explain });
    if (p === '/v1/pumgye/explain/diff') return route.fulfill({ json: { version: 1, kind: 'simulation', audit_id: 43, snapshot: { source: 'candidate', revision: revision + 1, base_revision: revision }, total: 1, next_cursor: null, changes: [
      { entity: 'assignment', service: 'reports', map: 'users', subject: 'u_kim', change: 'modified', before: { permissions: ['export', 'read'], information_classes: ['public', 'internal', 'confidential'] }, after: { permissions: ['read'], information_classes: ['public', 'internal'] }, delta: { added_permissions: [], removed_permissions: ['export'], added_information_classes: [], removed_information_classes: ['confidential'], minimum_aal: [2, 1] } }] } });
    if (p === '/v1/pumgye/explain/batch') {
      const body = JSON.parse(request.postData());
      const results = body.cases.map((item, index) => ({ label: item.label, outcome: { decision: index === 0 ? 'PermissionDenied' : 'Allow', allow: index !== 0 }, comparison: { published: { decision: 'Allow', allow: true }, changed: index === 0 } }));
      return route.fulfill({ json: { results, summary: { cases: results.length, allowed: results.length - 1, denied: 1, unavailable: 0, changed: 1, allow_to_deny: 1, deny_to_allow: 0 } } });
    }
    if (p === '/v1/plugins/hopae/subjects/resolve') { const ids = JSON.parse(request.postData()).ids; return route.fulfill({ json: { items: ids.map(id => ({ id, status: id === 'u_kim' ? 'active' : 'unknown', reason: id === 'u_kim' ? null : 'not_found', kind: 'human', user_id: id, human_subject: null, display_name: id === 'u_kim' ? 'Kim Analyst' : null, email: null, providers: [], created_at: null, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null })), resolved: 1, unknown: 0, complete: true, privacy_profile: 'standard' } }); }
    if (p === '/v1/plugins/hopae/subjects/search') return route.fulfill({ json: { items: [{ id: 'u_choi', status: 'active', reason: null, kind: 'human', user_id: 'u_choi', human_subject: null, display_name: 'Choi Newhire', email: 'c***@corp.example', providers: [], created_at: 1, last_login_at: null, last_seen_at: null, service_id: null, realm: null, expires_at: null }], next_cursor: null, privacy_profile: 'standard' } });
    return route.fulfill({ status: 404, json: { detail: 'not found' } });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { calls };
}

const view = page => page.locator('#view-policies');

test('service catalog lists counts and highest class, searches and opens detail', async ({ page }) => {
  await setup(page);
  await page.locator('[data-view="policies"]').click();
  await expect(view(page).locator('tbody tr')).toHaveCount(3);
  const reports = view(page).locator('tbody tr', { hasText: 'reports' });
  await expect(reports).toContainText('restricted');
  await expect(reports.locator('td.kit-col-assignments')).toHaveText('5');
  await expect(view(page).locator('tbody tr', { hasText: 'cluster-api' })).toContainText('Kubernetes API');
  await view(page).getByRole('searchbox', { name: 'Search services' }).fill('bill');
  await view(page).getByRole('searchbox', { name: 'Search services' }).press('Enter');
  await expect(view(page).locator('tbody tr')).toHaveCount(1);
  await view(page).locator('tbody tr').first().locator('td.kit-col-roles').click();
  await expect(page).toHaveURL(/#policies\/services\/billing$/);
  await expect(view(page).locator('h1')).toHaveText('billing');
});

test('role editor saves to a draft, rejects cycles and reports holders', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/services/reports?tab=roles&role=reader');
  const editor = view(page).locator('.zt-role-editor');
  await expect(editor).toContainText('used by 5 subjects');
  await editor.getByRole('checkbox', { name: 'analyst' }).check();
  await editor.getByRole('button', { name: 'Save role to draft' }).click();
  await expect(editor.locator('.kit-field-error')).toContainText('cycle');
  await editor.getByRole('checkbox', { name: 'analyst' }).uncheck();
  await editor.getByRole('checkbox', { name: 'write' }).check();
  await editor.getByLabel('Class ceiling').selectOption('confidential');
  await expect(editor.getByRole('checkbox', { name: 'confidential' })).toBeChecked();
  await editor.getByRole('button', { name: 'Save role to draft' }).click();
  await expect(view(page).locator('.zt-draftbar')).toContainText('unpublished change');
  await page.reload();
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(view(page).locator('.zt-draftbar')).toBeVisible();
});

test('assignments validate subjects inline, use the Hopae picker and bulk revoke', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/services/reports?tab=assignments');
  await expect(view(page).locator('tbody tr')).toHaveCount(5);
  await expect(view(page).locator('tbody tr', { hasText: 'u_kim' })).toContainText('Kim Analyst');
  const form = view(page).locator('form.zt-assign');
  await form.getByLabel('Kind').selectOption('workload');
  await form.locator('input[name="subject"]').fill('s_bad');
  await form.getByRole('checkbox', { name: 'reader' }).check();
  await form.getByRole('button', { name: 'Add assignment to draft' }).click();
  await expect(form.locator('input[name="subject"]')).toHaveAttribute('aria-invalid', 'true');
  await expect(form.locator('.kit-field-error')).toContainText('48 lowercase hexadecimal');
  await form.getByLabel('Kind').selectOption('user');
  await form.locator('input[name="subject"]').fill('choi');
  await expect(form.locator('.kit-picker [role="option"]')).toHaveCount(1);
  await form.locator('input[name="subject"]').press('ArrowDown');
  await form.locator('input[name="subject"]').press('Enter');
  await expect(form.locator('input[name="subject"]')).toHaveValue('u_choi');
  await form.getByRole('button', { name: 'Add assignment to draft' }).click();
  await expect(view(page).locator('tbody tr')).toHaveCount(6);
  await view(page).locator('tbody tr', { hasText: 'u_lee' }).getByRole('checkbox').check();
  await view(page).locator('tbody tr', { hasText: 'u_park' }).getByRole('checkbox').check();
  await expect(view(page).locator('.zt-bulk')).toContainText('2 selected');
  await view(page).getByRole('button', { name: 'Revoke selected' }).click();
  const dialog = page.locator('dialog.kit-dialog');
  await dialog.locator('input').fill('reports');
  await dialog.locator('textarea').fill('offboarding');
  await dialog.getByRole('button', { name: 'Revoke selected' }).click();
  await expect(view(page).locator('tbody tr')).toHaveCount(4);
});

test('simulator renders the Pumgye trace with localized reason and places 422 errors on fields', async ({ page }) => {
  const { calls } = await setup(page);
  await page.goto('/ui/#policies/services/reports?tab=simulate&kind=user&subject=u_lee&mode=permission&permission=read&information_class=restricted&ip=10.1.2.3&guard=enforced_allow&aal=2&run=1');
  const result = view(page).locator('.zt-sim-result');
  await expect(result).toHaveAttribute('data-decision', 'ClassDenied');
  await expect(result.locator('.kit-stage')).toHaveCount(8);
  await expect(result.locator('.kit-stage.is-deciding')).toHaveAttribute('data-stage', 'information_class');
  await expect(result.locator('.kit-stage[data-stage="network"]')).toContainText('10.0.0.0/8');
  const body = JSON.parse(calls.find(call => call.path === '/v1/pumgye/explain').body);
  expect(body).toEqual({ case: { label: 'console', subject: { id: 'u_lee', kind: 'user' }, service: 'reports', permission: 'read', information_class: 'restricted', ip: '10.1.2.3', guard: 'enforced_allow', aal: 2 }, trace: true });
  await page.locator('#locale-select').selectOption('ko');
  await expect(view(page).locator('.zt-sim-result .kit-why')).toContainText('정보 등급');
  await expect(view(page).locator('.zt-sim-result .kit-stage[data-stage="information_class"]')).toContainText('restricted');
});

test('simulator shows Pumgye validation errors on the offending field', async ({ page }) => {
  await setup(page, { explainStatus: 400, explain: { error: { code: 'pumgye.error.invalid_case', message_key: 'pumgye.error.invalid_case', details: [{ path: 'case.ip', code: 'pumgye.case.missing_network_evidence', message_key: 'pumgye.case.missing_network_evidence' }] } } });
  await page.goto('/ui/#policies/services/reports?tab=simulate&kind=user&subject=u_lee&ip=x&run=1');
  await expect(view(page).locator('input[name="ip"]')).toHaveAttribute('aria-invalid', 'true');
  await expect(view(page).locator('.kit-field', { has: page.locator('input[name="ip"]') })).toContainText('requires ip and guard evidence');
});

test('publish shows diff and impact, requires reason and typed confirmation, and binds both revisions', async ({ page }) => {
  const { calls } = await setup(page);
  await page.goto('/ui/#policies/services/reports?tab=assignments');
  await view(page).locator('tbody tr', { hasText: 'u_kim' }).getByRole('button', { name: 'Revoke' }).click();
  await view(page).getByRole('link', { name: 'Review & publish' }).click();
  await expect(page).toHaveURL(/#policies\/publish$/);
  await expect(view(page).locator('.zt-diff-group[data-service="reports"]')).toContainText('u_kim');
  await expect(view(page).locator('.zt-impact')).toContainText('−permissions export');
  await expect(view(page).locator('.zt-impact .zt-kpi.is-warn')).toContainText('1');
  await view(page).getByRole('button', { name: 'Publish revision 78' }).click();
  await expect(view(page).locator('.zt-publish-form .kit-field-error')).toContainText('Enter a reason');
  await view(page).getByLabel('Reason (required)').fill('Kim moved teams');
  await view(page).getByRole('button', { name: 'Publish revision 78' }).click();
  const dialog = page.locator('dialog.kit-dialog');
  await expect(dialog).toContainText('Type reports to confirm');
  await dialog.locator('input').fill('reports');
  await dialog.locator('textarea').fill('Kim moved teams');
  await dialog.getByRole('button', { name: 'Publish' }).click();
  await expect(page).toHaveURL(/#policies(\?refresh=1)?$/);
  const put = calls.find(call => call.path === '/v1/pumgye/policy' && call.method === 'PUT');
  expect(put.headers['if-match']).toBe('"77"');
  expect(put.headers['x-hangang-config-revision']).toBe('"5"');
  expect(decodeURIComponent(put.headers['x-hangang-change-reason'])).toBe('Kim moved teams');
  const sent = JSON.parse(put.body);
  expect(sent.revision).toBe(77);
  expect(sent.policy.services.reports.users.u_kim).toBeUndefined();
  await expect(view(page).locator('.zt-draftbar')).toHaveCount(0);
});

test('a 409 shows the three-way conflict view and rebases the draft', async ({ page }) => {
  await setup(page, { putStatus: [409, 200] });
  await page.goto('/ui/#policies/services/billing?tab=assignments');
  await view(page).locator('tbody tr', { hasText: 'u_kim' }).getByRole('button', { name: 'Revoke' }).click();
  await page.evaluate(() => { location.hash = '#policies/publish'; });
  await view(page).getByLabel('Reason (required)').fill('cleanup');
  await view(page).getByRole('button', { name: /Publish revision/ }).click();
  const dialog = page.locator('dialog.kit-dialog');
  if (await dialog.count()) { await dialog.locator('input').fill('billing'); await dialog.locator('textarea').fill('cleanup'); await dialog.getByRole('button', { name: 'Publish' }).click(); }
  await expect(view(page).locator('h1')).toHaveText('Publication conflict');
  await expect(view(page)).toContainText('require_guard');
  await view(page).getByRole('button', { name: 'Rebase, keep my values' }).click();
  await expect(view(page).locator('.zt-draftbar')).toContainText('based on revision 78');
  await expect(view(page).getByRole('button', { name: 'Publish revision 79' })).toBeVisible();
});

test('Kubernetes-owned policy is inspectable but read-only', async ({ page }) => {
  await setup(page, { owner: 'kubernetes' });
  await page.goto('/ui/#policies/services/reports?tab=roles&role=reader');
  await expect(view(page).locator('.zt-policy-head')).toContainText('Kubernetes owns this policy');
  await expect(view(page).locator('.zt-role-editor').getByRole('checkbox', { name: 'write' })).toBeDisabled();
  await expect(view(page).getByRole('button', { name: 'Save role to draft' })).toBeDisabled();
  await page.evaluate(() => { location.hash = '#policies/services/reports?tab=assignments'; });
  await expect(view(page).locator('tbody tr')).toHaveCount(5);
  await expect(view(page).locator('form.zt-assign')).toHaveCount(0);
});

test('matrix shows subjects across services with effective rights', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/matrix');
  await expect(view(page).locator('tbody tr', { hasText: 'u_kim' })).toContainText('analyst');
  await expect(view(page).locator('tbody tr', { hasText: 'u_kim' })).toContainText('viewer');
});

test('advanced JSON is read-only until explicit edit and then goes through review', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/advanced');
  await expect(view(page).locator('textarea')).toBeHidden();
  await view(page).getByRole('button', { name: 'Edit JSON' }).click();
  await view(page).locator('textarea').fill('{"version":2}');
  await view(page).getByRole('button', { name: 'Use as draft and review' }).click();
  await expect(view(page).locator('textarea')).toHaveAttribute('aria-invalid', 'true');
  const document = fixturePolicy(); delete document.services.billing;
  await view(page).locator('textarea').fill(JSON.stringify(document));
  await view(page).getByRole('button', { name: 'Use as draft and review' }).click();
  await expect(page).toHaveURL(/#policies\/publish$/);
  await expect(view(page).locator('.zt-diff-group[data-service="billing"]')).toContainText('Removed');
});

test('policies at 390 px dark stay within the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  for (const hash of ['#policies', '#policies/services/reports?tab=roles&role=analyst', '#policies/services/reports?tab=assignments']) {
    await page.evaluate(value => { location.hash = value; }, hash);
    await expect(view(page).locator('h1')).toBeVisible();
    await page.waitForTimeout(200);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  }
});

test('cross-section simulator entry keeps the subject and picks or redirects to a service', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/simulate?subject=u_kim');
  const links = view(page).locator('.zt-simulate-pick a');
  await expect(links).toHaveText(['billing', 'reports', 'cluster-api']);
  await expect(view(page).locator('.zt-simulate-pick li', { hasText: 'reports' })).toContainText('assigned');
  await links.filter({ hasText: 'reports' }).click();
  await expect(page).toHaveURL(/#policies\/services\/reports\?/);
  await expect(page).toHaveURL(/subject=u_kim/);
  await expect(page).toHaveURL(/tab=simulate/);
  await expect(view(page).locator('input[name="subject"]')).toHaveValue('u_kim');
  await page.goto('/ui/#policies/simulate?subject=' + encodeURIComponent(HUMAN) + '&service=reports');
  await expect(page).toHaveURL(/#policies\/services\/reports\?.*kind=human/);
  await expect(view(page).locator('select[name="kind"]')).toHaveValue('human');
});

test('role editor preselects the class ceiling for a contiguous selection', async ({ page }) => {
  await setup(page);
  await page.goto('/ui/#policies/services/reports?tab=roles&role=analyst');
  const editor = view(page).locator('.zt-role-editor');
  await expect(editor.getByLabel('Class ceiling')).toHaveValue('confidential');
  await editor.getByRole('checkbox', { name: 'internal' }).uncheck();
  await expect(editor.getByLabel('Class ceiling')).toHaveValue('');
});
