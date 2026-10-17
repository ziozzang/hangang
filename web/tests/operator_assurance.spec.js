import { test, expect } from '@playwright/test';

// Console operator assurance (Hopae ADR-0021) in the header: the AAL badge of
// a Hopae SSO session, the step-up redirect a step-up answer causes, and the
// break-glass label of a local administrator session.
const status = { revision: 7, http_routes: 0, tcp_routes: 0, metrics: { requests_total: 0, errors_total: 0, active_connections: 0 }, state: { ready: true, draining: false }, uptime_seconds: 1, version: 'test', process_id: 1 };
const operator = { id: 7, username: 'operator', role: 'viewer', enabled: true };
const policy = { minimum_aal: 2, require_factor: 'webauthn', sensitive_max_age_seconds: 120, step_up_url: '/ui/step-up?return=%2Fui%2F' };
const assurance = (overrides = {}) => ({ v: 2, kid: 'op-1', aud: 'hangang-console', app: 'console', host: 'console.example.test', sub: 'u_op', sid: 's_op', aal: 2, factor: 'webauthn', factor_at: 1, high_assurance: false, auth_time: 1, require_aal: 2, require_factor: 'webauthn', satisfied: true, grace: false, iat: 1, exp: 2, ...overrides });
const stepUp = (error = 'operator_step_up_required') => ({ status: 403, json: { error, step_up_url: '/ui/step-up?return=%2Fui%2F' } });

async function fixtures(page, routes = {}) {
  const calls = [];
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), p = url.pathname;
    if (p === '/ui/step-up') {
      calls.push({ path: p, search: url.search });
      return route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Step-up</title><p>step-up landing</p>' });
    }
    if (p.startsWith('/ui/')) return route.continue();
    calls.push({ path: p, method: request.method(), headers: request.headers() });
    if (routes[p]) return routes[p](route, calls);
    if (p === '/v1/auth/setup') return route.fulfill({ json: { bootstrap_required: false } });
    if (p === '/v1/auth/sso/config') return route.fulfill({ json: { provider: 'hopae', login_url: '/_hopae/login?return=%2Fui%2F%3Fsso%3Dhopae' } });
    if (p === '/v1/auth/me') return route.fulfill({ json: { user: operator } });
    if (p === '/v1/status') return route.fulfill({ json: status });
    if (p === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    return route.fulfill({ status: 404, json: { error: 'missing fixture' } });
  });
  return calls;
}

const hopaeSignIn = { '/v1/auth/sso/exchange': route => route.fulfill({ json: { token: 'hsso_fixture', user: operator, assurance: assurance() } }) };

test('a Hopae passkey session shows its AAL badge with the freshness policy', async ({ page }) => {
  await fixtures(page, { ...hopaeSignIn, '/v1/auth/sso/session': route => route.fulfill({ json: { method: 'hopae', account: 'operator', assurance: assurance(), policy } }) });
  await page.goto('/ui/?sso=hopae');
  const badge = page.locator('#operator-assurance');
  await expect(badge).toBeVisible();
  await expect(badge).toHaveText('AAL2 · Passkey');
  await expect(badge).toHaveClass(/is-strong/);
  await expect(badge).toHaveAttribute('title', /within 120 seconds/);
  await expect(badge).toHaveAttribute('role', 'status');
});

test('a security key at AAL3 and an enrollment-grace session are labelled distinctly', async ({ page }) => {
  let current = assurance({ aal: 3, high_assurance: true });
  await fixtures(page, { ...hopaeSignIn, '/v1/auth/sso/session': route => route.fulfill({ json: { method: 'hopae', account: 'operator', assurance: current, policy } }) });
  await page.goto('/ui/?sso=hopae');
  const badge = page.locator('#operator-assurance');
  await expect(badge).toHaveText('AAL3 · Security key');
  current = assurance({ aal: 1, factor: null, factor_at: null, satisfied: false, grace: true });
  await page.reload();
  await expect(badge).toHaveText('AAL1 · passkey enrollment pending');
  await expect(badge).toHaveClass(/is-warning/);
  await expect(badge).not.toHaveClass(/is-strong/);
});

test('a step-up answer at sign-in sends the operator to the step-up landing', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/auth/sso/exchange': route => route.fulfill(stepUp()) });
  await page.goto('/ui/?sso=hopae');
  await expect(page).toHaveURL(/\/ui\/step-up\?return=%2Fui%2F(%23[a-z-]+)?$/);
  await expect(page.getByText('step-up landing')).toBeVisible();
  expect(calls.filter(c => c.path === '/ui/step-up')).toHaveLength(1);
});

test('a reauthentication answer mid-session returns to the current view after step-up', async ({ page }) => {
  let stale = false;
  await fixtures(page, {
    ...hopaeSignIn,
    '/v1/auth/sso/session': route => route.fulfill({ json: { method: 'hopae', account: 'operator', assurance: assurance(), policy } }),
    '/v1/status': route => route.fulfill(stale ? stepUp('operator_reauthentication_required') : { json: status }),
  });
  await page.goto('/ui/?sso=hopae#status');
  await expect(page.locator('#operator-assurance')).toHaveText('AAL2 · Passkey');
  stale = true;
  await page.reload();
  await expect(page).toHaveURL(/\/ui\/step-up\?return=%2Fui%2F%23status$/);
});

test('the session read never redirects: a step-up answer there only hides the badge', async ({ page }) => {
  const calls = await fixtures(page, { ...hopaeSignIn, '/v1/auth/sso/session': route => route.fulfill(stepUp()) });
  await page.goto('/ui/?sso=hopae');
  await expect(page.locator('#signed-in-user')).toHaveText('operator · viewer');
  await expect.poll(() => calls.filter(c => c.path === '/v1/auth/sso/session').length).toBeGreaterThan(0);
  await expect(page.locator('#operator-assurance')).toBeHidden();
  expect(page.url()).not.toContain('/ui/step-up');
});

test('a break-glass local administrator session is labelled and warned', async ({ page }) => {
  await fixtures(page, {
    '/v1/auth/login': route => route.fulfill({ json: { token: 'local-session', expires_in_seconds: 28800, user: operator } }),
    '/v1/auth/sso/session': route => route.fulfill({ json: { method: 'local', account: 'operator', break_glass: true } }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('operator');
  await page.locator('#login-password').fill('owned fixture password');
  await page.locator('#login-submit').click();
  const badge = page.locator('#operator-assurance');
  await expect(badge).toHaveText('Break-glass (local)');
  await expect(badge).toHaveClass(/is-warning/);
  await expect(badge).toHaveAttribute('title', /Every change is audited/);
});

test('without console SSO a local session shows no badge', async ({ page }) => {
  await fixtures(page, {
    '/v1/auth/sso/config': route => route.fulfill({ status: 404, json: { error: 'unknown console endpoint' } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'local-session', expires_in_seconds: 28800, user: operator } }),
    '/v1/auth/sso/session': route => route.fulfill({ status: 404, json: { error: 'unknown console endpoint' } }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('operator');
  await page.locator('#login-password').fill('owned fixture password');
  await page.locator('#login-submit').click();
  await expect(page.locator('#signed-in-user')).toHaveText('operator · viewer');
  await expect(page.locator('#operator-assurance')).toBeHidden();
});
