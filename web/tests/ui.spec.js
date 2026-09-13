import { test, expect } from '@playwright/test';

const status = { revision: 7, http_routes: 1, tcp_routes: 1, metrics: { requests_total: 1284, errors_total: 2, active_connections: 4, rejected_connections_total: 3, policy_errors_total: 1, config_updates_total: 6 }, state: { draining: false }, uptime_seconds: 7384, version: '0.9.1', process_id: 4242 };
const config = { revision: 7, certificates: [], http: [{ id: 'api', path_prefix: '/', headers: {}, json: {}, backends: ['http://127.0.0.1:8080'], deny_cidrs: [], lua: null }], tcp: [{ id: 'db', sni: null, listen: '127.0.0.1:9001', backends: ['127.0.0.1:5432'], deny_cidrs: [] }] };
const CREDENTIAL = `alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`;

async function fixtures(page, overrides = {}) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const req = route.request(); const url = new URL(req.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, method: req.method(), headers: req.headers(), body: req.postData() });
    if (url.pathname.startsWith('/v1/routes/http') && ['POST', 'PUT'].includes(req.method())) {
      const draft = req.postDataJSON();
      if (Object.hasOwn(draft, 'hosts') && (!Array.isArray(draft.hosts) || draft.hosts.length === 0)) {
        return route.fulfill({ status: 422, json: { title: 'Configuration Invalid', detail: 'hosts must contain at least one pattern' }, contentType: 'application/problem+json' });
      }
    }
    if (overrides[url.pathname]) return overrides[url.pathname](route, calls);
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle', current_version: '0.1.0', last_check_unix: 0, detail: null } });
    if (url.pathname === '/v1/status') return route.fulfill({ json: status });
    if (url.pathname === '/healthz') return route.fulfill({ body: 'ok\n', contentType: 'text/plain' });
    if (url.pathname === '/metrics') return route.fulfill({ body: '# HELP hangang_requests_total Requests\nhangang_requests_total 1284\n', contentType: 'text/plain; version=0.0.4' });
    if (url.pathname === '/v1/cache') return route.fulfill({ json: { enabled: false, config: null, stats: null, active_fills: 0 } });
    if (url.pathname === '/v1/cache/purge') return route.fulfill({ json: { purged: true } });
    if (url.pathname === '/v1/config') return route.fulfill({ json: config, headers: { etag: '"7"' } });
    if (url.pathname === '/v1/config/validate') return route.fulfill({ json: { valid: true, revision: 7 } });
    if (url.pathname === '/v1/routes/http') return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
    if (url.pathname === '/v1/routes/tcp') return route.fulfill({ json: { revision: 7, routes: config.tcp }, headers: { etag: '"7"' } });
    for (const type of ['http', 'tcp']) {
      const prefix = `/v1/routes/${type}/`;
      if (url.pathname.startsWith(prefix) && req.method() === 'GET') {
        const found = config[type].find((item) => item.id === decodeURIComponent(url.pathname.slice(prefix.length)));
        return found ? route.fulfill({ json: found, headers: { etag: '"7"' } }) : route.fulfill({ status: 404, json: { title: 'Not Found', status: 404, detail: 'route not found' }, contentType: 'application/problem+json' });
      }
    }
    if (url.pathname === '/openapi.json') return route.fulfill({ json: { openapi: '3.0.3', info: { title: 'Hangang Admin API', version: '1' }, paths: { '/v1/status': { get: { summary: 'Runtime status', responses: { 200: { description: 'OK' } } } } }, components: { schemas: { Status: { type: 'object', properties: { revision: { type: 'integer' } } } } } } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  return calls;
}

async function login(page, token = 'correct-token') {
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.getByRole('dialog', { name: 'Connect to this proxy' })).toBeHidden();
}

function sectionByTitle(page, title) {
  return page.locator('details.form-section', { has: page.locator('summary .section-title', { hasText: new RegExp(`^${title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }) });
}

/** Expand a collapsed editor section by its title (a no-op when it is already open). */
async function openSection(page, title) {
  const details = sectionByTitle(page, title);
  await expect(details).toHaveCount(1);
  if (!(await details.evaluate((el) => el.open))) await details.locator('summary').click();
  await expect(details).toHaveJSProperty('open', true);
}

function routeWrites(calls, path, method) { return calls.filter((call) => call.path === path && call.method === method); }

test('authenticates in memory and renders live status accessibly', async ({ page }) => {
  const calls = await fixtures(page);
  await login(page, 'secret-value');
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
  await expect(page.locator('#metric-grid').getByText('1,284')).toBeVisible();
  await expect(page.locator('#runtime-state')).toHaveText('Accepting traffic');
  await expect(page.locator('#server-version')).toHaveText('0.9.1');
  await expect(page.locator('#process-id')).toHaveText('4242');
  expect(calls.find((call) => call.path === '/v1/status').headers.authorization).toBe('Bearer secret-value');
  const stored = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage), cookie: document.cookie, url: location.href, input: document.querySelector('#token-input').value }));
  expect(stored).toEqual({ local: [], session: [], cookie: '', url: 'http://127.0.0.1:41739/ui/#status', input: '' });
});

test('rejects a bad token without retaining it', async ({ page }) => {
  await fixtures(page, { '/v1/status': (route) => route.fulfill({ status: 401, body: 'unauthorized' }) });
  await page.goto('/ui/'); await page.getByLabel('Administrator token').fill('bad-token'); await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.getByText('That administrator token was rejected.')).toBeVisible();
  await expect(page.getByLabel('Administrator token')).toHaveValue('bad-token');
});

test('first-run setup requires the existing token and stores only the account session in this tab', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: true } }),
    '/v1/auth/bootstrap': route => route.fulfill({ status: 201, json: { user: { id: 'owner', username: 'owner', role: 'admin', enabled: true } } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'session-secret', expires_in_seconds: 28800, user: { id: 'owner', username: 'owner', role: 'admin', enabled: true } } }),
    '/v1/auth/logout': route => route.fulfill({ status: 204, body: '' }),
  });
  await page.goto('/ui/');
  await expect(page.getByRole('heading', { name: 'Create the first administrator' })).toBeVisible();
  await page.getByLabel('Bootstrap authorization token').fill('bootstrap-secret');
  await page.getByLabel('New administrator username').fill('owner');
  await page.getByLabel('New password', { exact: true }).fill('a-strong-password');
  await page.getByLabel('Confirm password').fill('a-strong-password');
  await page.getByRole('button', { name: 'Create administrator' }).click();
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeHidden();
  await expect(page.locator('#signed-in-user')).toHaveText('owner · admin');
  const bootstrap = calls.find(call => call.path === '/v1/auth/bootstrap');
  expect(bootstrap.headers.authorization).toBe('Bearer bootstrap-secret');
  expect(JSON.parse(bootstrap.body)).toEqual({ username: 'owner', password: 'a-strong-password' });
  expect(calls.find(call => call.path === '/v1/status').headers.authorization).toBe('Bearer session-secret');
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), sessionToken: sessionStorage.getItem('hangang.account.session.v1'), sessionLength: sessionStorage.length, cookie: document.cookie, password: document.querySelector('#login-password').value, setup: document.querySelector('#setup-token').value }))).toEqual({ local: [], sessionToken: 'session-secret', sessionLength: 1, cookie: '', password: '', setup: '' });
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('hangang.account.session.v1'))).toBeNull();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await expect.poll(() => calls.filter(call => call.path === '/v1/auth/logout').length).toBe(1);
  expect(calls.find(call => call.path === '/v1/auth/logout').headers.authorization).toBe('Bearer session-secret');
});

test('account session survives same-tab reload only after the server revalidates it', async ({ page }) => {
  const user = { id: 'owner', username: 'owner', role: 'admin', enabled: true };
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'account-session', expires_in_seconds: 28800, user } }),
    '/v1/auth/me': route => route.fulfill({ json: { user } }),
    '/v1/auth/logout': route => route.fulfill({ status: 204, body: '' }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('owner');
  await page.locator('#login-password').fill('owner-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeHidden();
  // The token must exist at the first visible signed-in moment, even if
  // subsequent dashboard loads are still in flight when F5 is pressed.
  expect(await page.evaluate(() => sessionStorage.getItem('hangang.account.session.v1'))).toBe('account-session');

  const before = calls.length;
  await page.reload();
  await expect(page.locator('#signed-in-user')).toHaveText('owner · admin');
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeHidden();
  const restored = calls.slice(before);
  expect(restored.filter(call => call.path === '/v1/auth/login')).toHaveLength(0);
  expect(restored.find(call => call.path === '/v1/auth/me')?.headers.authorization).toBe('Bearer account-session');
  expect(restored.find(call => call.path === '/v1/status')?.headers.authorization).toBe('Bearer account-session');
  expect(restored.findIndex(call => call.path === '/v1/auth/me')).toBeLessThan(restored.findIndex(call => call.path === '/v1/status'));

  await page.getByRole('button', { name: 'Log out' }).click();
  expect(await page.evaluate(() => sessionStorage.getItem('hangang.account.session.v1'))).toBeNull();
  await page.reload();
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeVisible();
  expect(calls.slice(before).filter(call => call.path === '/v1/auth/login')).toHaveLength(0);
});

test('invalid saved account session is removed before any protected data loads', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/me': route => route.fulfill({ status: 401, body: 'unauthorized' }),
  });
  await page.goto('/ui/');
  await page.evaluate(() => sessionStorage.setItem('hangang.account.session.v1', 'revoked-session'));
  const before = calls.length;
  await page.reload();
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('hangang.account.session.v1'))).toBeNull();
  expect(calls.slice(before).filter(call => call.path === '/v1/status' || call.path === '/v1/config')).toHaveLength(0);
});

test('restored viewer role is applied before an administrator deep link loads', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/me': route => route.fulfill({ json: { user: { id: 'viewer', username: 'viewer', role: 'viewer', enabled: true } } }),
  });
  await page.goto('/ui/#config');
  await page.evaluate(() => sessionStorage.setItem('hangang.account.session.v1', 'viewer-session'));
  const before = calls.length;
  await page.reload();
  await expect(page.locator('#signed-in-user')).toHaveText('viewer · viewer');
  await expect(page).toHaveURL(/#status$/);
  await expect(page.getByRole('link', { name: 'Configuration' })).toBeHidden();
  expect(calls.slice(before).filter(call => call.path === '/v1/config' || call.path === '/v1/users')).toHaveLength(0);
});

test('standalone Basic credential utility clears passwords and never publishes a route', async ({ page }) => {
  const user = { id: 'owner', username: 'owner', role: 'admin', enabled: true };
  let hashes = 0;
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'account-session', user } }),
    '/v1/util/hash-password': route => {
      hashes += 1;
      return hashes === 1
        ? route.fulfill({ json: { username: 'alice', credential: 'alice:salt:hash' } })
        : route.fulfill({ status: 404, body: 'unavailable' });
    },
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('owner');
  await page.locator('#login-password').fill('owner-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Utilities' }).click();
  const form = page.locator('#utility-hash-form');
  await form.locator('[name="username"]').fill('alice');
  await form.locator('[name="password"]').fill('first-password');
  await form.getByRole('button', { name: 'Generate credential' }).click();
  await expect(page.locator('#utility-credential')).toHaveValue('alice:salt:hash');
  await expect(form.locator('[name="password"]')).toHaveValue('');
  await expect(page.locator('#utility-copy-credential')).toBeEnabled();
  expect(JSON.parse(calls.find(call => call.path === '/v1/util/hash-password').body)).toEqual({ username: 'alice', password: 'first-password' });
  expect(calls.filter(call => call.path.startsWith('/v1/routes/') && call.method !== 'GET')).toHaveLength(0);

  await form.locator('[name="password"]').fill('second-password');
  await form.getByRole('button', { name: 'Generate credential' }).click();
  await expect(page.locator('#utility-credential')).toHaveValue('');
  await expect(page.locator('#utility-copy-credential')).toBeDisabled();
  await expect(form.locator('[name="password"]')).toHaveValue('');
  await expect(page.locator('#utility-hash-message')).toContainText('does not offer password hashing');
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#utility-credential')).toHaveValue('');
});

test('viewer can verify their session but cannot open administrator utilities', async ({ page }) => {
  const viewer = { id: 'reader', username: 'reader', role: 'viewer', enabled: true };
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'viewer-session', user: viewer } }),
    '/v1/auth/me': route => route.fulfill({ json: { user: viewer } }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('reader');
  await page.locator('#login-password').fill('viewer-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('link', { name: 'Utilities' })).toBeHidden();
  await page.getByRole('button', { name: 'Verify my session' }).click();
  await expect(page.locator('#session-result')).toContainText('reader · viewer');
  expect(calls.find(call => call.path === '/v1/auth/me')?.headers.authorization).toBe('Bearer viewer-session');
  await page.evaluate(() => { location.hash = '#utilities'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter(call => call.path === '/v1/util/hash-password')).toHaveLength(0);
});

test('session verification clears administrator data after a role downgrade', async ({ page }) => {
  await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'account-session', user: { id: 'owner', username: 'owner', role: 'admin', enabled: true } } }),
    '/v1/auth/me': route => route.fulfill({ json: { user: { id: 'owner', username: 'owner', role: 'viewer', enabled: true } } }),
    '/v1/auth/logout': route => route.fulfill({ status: 204 }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('owner');
  await page.locator('#login-password').fill('owner-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.locator('#utility-credential').evaluate(element => { element.value = 'sensitive-credential'; });
  await page.getByRole('button', { name: 'Verify my session' }).click();
  await expect(page.getByRole('dialog', { name: 'Sign in' })).toBeVisible();
  await expect(page.locator('#utility-credential')).toHaveValue('');
  await expect(page.getByRole('link', { name: 'Utilities' })).toBeHidden();
});

test('viewer sign-in shows status and cannot navigate to administrator controls', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'viewer-session', expires_in_seconds: 28800, user: { id: 'viewer-1', username: 'viewer', role: 'viewer', enabled: true } } }),
    '/v1/status': route => route.fulfill({ json: { ...status, state: { supervised: true } } }),
    '/v1/update/status': route => route.fulfill({ json: { enabled: true, phase: 'idle', current_version: '0.9.1' } }),
  });
  await page.goto('/ui/#config');
  await page.locator('#login-username').fill('viewer');
  await page.locator('#login-password').fill('viewer-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'HTTP routes' })).toBeHidden();
  await expect(page.getByRole('link', { name: 'Users' })).toBeHidden();
  await expect(page.locator('#restart-server')).toBeHidden();
  await expect(page.locator('#check-update')).toBeHidden();
  await page.evaluate(() => { location.hash = '#users'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter(call => call.path === '/v1/users' || call.path === '/v1/config')).toHaveLength(0);
});

test('administrator creates, edits, and deletes local users', async ({ page }) => {
  const users = [{ id: 'owner', username: 'owner', role: 'admin', enabled: true }];
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'admin-session', expires_in_seconds: 28800, user: users[0] } }),
    '/v1/auth/me': route => route.fulfill({ json: { user: users[0] } }),
    '/v1/users': route => {
      if (route.request().method() === 'POST') {
        const body = JSON.parse(route.request().postData());
        users.push({ id: 'alice', username: body.username, role: body.role, enabled: true });
        return route.fulfill({ status: 201, json: users.at(-1) });
      }
      return route.fulfill({ json: { users } });
    },
    '/v1/users/alice': route => {
      if (route.request().method() === 'DELETE') { users.splice(1, 1); return route.fulfill({ status: 204, body: '' }); }
      Object.assign(users[1], JSON.parse(route.request().postData())); delete users[1].password;
      return route.fulfill({ json: users[1] });
    },
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('owner');
  await page.locator('#login-password').fill('owner-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
  const create = page.locator('#create-user-form');
  await create.locator('[name="username"]').fill('alice');
  await create.locator('[name="password"]').fill('alice-password');
  await create.getByRole('button', { name: 'Create user' }).click();
  const alice = page.locator('.user-card', { has: page.getByRole('heading', { name: 'alice' }) });
  await expect(alice).toBeVisible();
  await alice.locator('[name="role"]').selectOption('admin');
  await alice.locator('[name="enabled"]').uncheck();
  await alice.locator('[name="password"]').fill('new-alice-password');
  await alice.getByRole('button', { name: 'Save changes' }).click();
  await expect(alice.locator('.user-role')).toHaveText('admin · disabled');
  const update = calls.find(call => call.path === '/v1/users/alice' && call.method === 'PUT');
  expect(JSON.parse(update.body)).toEqual({ role: 'admin', enabled: false, password: 'new-alice-password' });
  await alice.getByRole('button', { name: 'Delete user' }).click();
  await page.getByRole('dialog', { name: 'Delete user?' }).getByRole('button', { name: 'Delete user' }).click();
  await expect(page.getByRole('heading', { name: 'alice' })).toHaveCount(0);
  expect(calls.filter(call => call.path === '/v1/users/alice' && call.method === 'DELETE')).toHaveLength(1);
});

test('user names render as text and duplicate creation stays on the form', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => route.fulfill({ json: { token: 'admin-session', expires_in_seconds: 28800, user: { id: 'owner', username: 'owner', role: 'admin', enabled: true } } }),
    '/v1/users': route => route.request().method() === 'POST'
      ? route.fulfill({ status: 409, contentType: 'application/problem+json', json: { title: 'Conflict', detail: 'User already exists.' } })
      : route.fulfill({ json: { users: [{ id: 'hostile', username: '<img src=x onerror=alert(1)>', role: 'viewer', enabled: true }] } }),
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('owner');
  await page.locator('#login-password').fill('owner-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page.getByRole('heading', { name: '<img src=x onerror=alert(1)>' })).toBeVisible();
  await expect(page.locator('.user-card img')).toHaveCount(0);
  const create = page.locator('#create-user-form');
  await create.locator('[name="username"]').fill('owner');
  await create.locator('[name="password"]').fill('another-password');
  await create.getByRole('button', { name: 'Create user' }).click();
  await expect(page.locator('#users-message')).toHaveText('User already exists.');
  await expect(create.locator('[name="username"]')).toHaveValue('owner');
  await expect(create.locator('[name="password"]')).toHaveValue('');
  expect(calls.filter(call => call.path === '/v1/users' && call.method === 'POST')).toHaveLength(1);
});

test('an old administrator response cannot repaint data after viewer sign-in', async ({ page }) => {
  let releaseConfig;
  const heldConfig = new Promise((resolve) => { releaseConfig = resolve; });
  let configStarted;
  const started = new Promise((resolve) => { configStarted = resolve; });
  await fixtures(page, {
    '/v1/auth/setup': route => route.fulfill({ json: { bootstrap_required: false } }),
    '/v1/auth/login': route => {
      const username = JSON.parse(route.request().postData()).username;
      return route.fulfill({ json: { token: `${username}-session`, expires_in_seconds: 28800, user: { id: username, username, role: username === 'admin' ? 'admin' : 'viewer', enabled: true } } });
    },
    '/v1/auth/logout': route => route.fulfill({ status: 204, body: '' }),
    '/v1/config': async route => {
      configStarted();
      await heldConfig;
      await route.fulfill({ json: { revision: 7, http: [{ id: 'private-secret-route', backends: ['http://127.0.0.1:8080'] }], tcp: [], certificates: [] } });
    },
  });
  await page.goto('/ui/');
  await page.locator('#login-username').fill('admin');
  await page.locator('#login-password').fill('admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Configuration' }).click();
  await started;
  await page.getByRole('button', { name: 'Log out' }).click();
  await page.locator('#login-username').fill('viewer');
  await page.locator('#login-password').fill('viewer-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  const lateResponse = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/config');
  releaseConfig();
  await lateResponse;
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
  await expect(page.locator('#config-editor')).toHaveValue('');
  await expect(page.getByRole('link', { name: 'Configuration' })).toBeHidden();
  await expect(page.locator('#signed-in-user')).toHaveText('viewer · viewer');
});

test('loads routes and creates an HTTP route with native fields', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ status: 201, json: { id: 'new-api', revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await expect(page.getByRole('heading', { name: 'api' })).toBeVisible();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('new-api');
  await page.getByLabel('Host match').fill('api.example.test');
  await page.getByLabel('Backends').fill('http://10.0.0.2:8080');
  await page.getByLabel('Denied CIDRs').fill('192.0.2.0/24');
  await page.getByLabel('Concurrent request limit').fill('32');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('new-api created.')).toBeVisible();
  const create = calls.find((call) => call.path === '/v1/routes/http' && call.method === 'POST');
  expect(create.headers['if-match']).toBe('"7"');
  const body = JSON.parse(create.body);
  expect(body).toMatchObject({ id: 'new-api', host: 'api.example.test', max_requests: 32, backends: ['http://10.0.0.2:8080'], deny_cidrs: ['192.0.2.0/24'], require_tls: false, retries: 0, upstream_timeout_ms: null, path_match: 'prefix', preserve_host: false, auth: null, basic_auth: null, balance: { mode: 'round_robin', weights: [], health: null }, response_set_headers: {}, response_remove_headers: [], upstream: { connect_address: null, dns_servers: [], socks5: null, tls: null } });
});

test('configuration conflict preserves draft and refreshes ETag before retry', async ({ page }) => {
  let puts = 0; let gets = 0;
  const calls = await fixtures(page, { '/v1/config': async (route) => {
    if (route.request().method() === 'PUT') { puts++; if (puts === 1) return route.fulfill({ status: 409, body: 'revision conflict' }); return route.fulfill({ json: { ...config, revision: 9, tcp: [] }, headers: { etag: '"9"' } }); }
    gets++; const revision = gets === 1 ? 7 : 8; return route.fulfill({ json: { ...config, revision }, headers: { etag: `"${revision}"` } });
  } });
  await login(page); await page.getByRole('link', { name: 'Configuration' }).click();
  const editor = page.getByLabel('JSON document'); const draft = JSON.stringify({ ...config, tcp: [] }, null, 2); await editor.fill(draft); await page.getByRole('button', { name: 'Apply configuration' }).click();
  await expect(page.getByText(/Revision conflict/)).toBeVisible(); await expect(editor).toHaveValue(draft);
  await page.getByRole('button', { name: 'Apply configuration' }).click();
  const writes = calls.filter((call) => call.path === '/v1/config' && call.method === 'PUT');
  expect(writes[0].headers['if-match']).toBe('"7"'); expect(writes[1].headers['if-match']).toBe('"8"');
  await expect(page.getByText('Revision 9 is active.')).toBeVisible();
});

test('a generic 422 on the whole document is explained by re-validating the same draft', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/config': (route) => route.request().method() === 'PUT'
      ? route.fulfill({ status: 422, body: 'configuration validation or activation failed; reload the current revision before retrying\n', contentType: 'text/plain' })
      : route.fulfill({ json: config, headers: { etag: '"7"' } }),
    '/v1/config/validate': (route) => route.fulfill({ status: 422, contentType: 'application/problem+json', json: { type: 'about:blank', title: 'Configuration Invalid', status: 422, detail: 'retries must be 0..16' } }),
  });
  await login(page); await page.getByRole('link', { name: 'Configuration' }).click();
  const draft = { ...config, http: [{ ...config.http[0], retries: 99 }] };
  await page.getByLabel('JSON document').fill(JSON.stringify(draft));
  await page.getByRole('button', { name: 'Apply configuration' }).click();
  await expect(page.locator('#config-message')).toHaveText('retries must be 0..16');
  const validate = calls.find((call) => call.path === '/v1/config/validate');
  expect(JSON.parse(validate.body)).toEqual(draft);
  expect(validate.headers.authorization).toBe('Bearer correct-token');
});

test('renders authenticated cache usage and purges cached responses after confirmation', async ({ page }) => {
  let cacheReads = 0;
  const cacheStatus = { enabled: true, config: { memory: { max_bytes: 67108864, max_entries: 10000, eviction: 'lru' }, disk: null, max_object_bytes: 1048576, max_fills: 32, fill_timeout_ms: 5000 }, stats: { memory_bytes: 2048, memory_entries: 2, disk_bytes: 0, disk_entries: 0, hits: 12, misses: 3, evictions: 1, errors: 0 }, active_fills: 1 };
  const calls = await fixtures(page, {
    '/v1/cache': route => { cacheReads++; return route.fulfill({ json: cacheStatus }); },
    '/v1/cache/purge': route => route.fulfill({ json: { purged: true } }),
  });
  await login(page); await page.getByRole('link', { name: 'Cache', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Cache', exact: true })).toBeVisible();
  await expect(page.locator('#cache-state')).toHaveText('Enabled');
  await expect(page.locator('#cache-memory-policy')).toContainText('64 MiB');
  await expect(page.locator('#cache-metric-grid')).toContainText('12');
  await page.getByRole('button', { name: 'Purge cache' }).click();
  const confirm = page.getByRole('dialog', { name: 'Purge the cache?' });
  await expect(confirm).toBeVisible();
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  expect(calls.filter(call => call.path === '/v1/cache/purge')).toHaveLength(0);
  await page.getByRole('button', { name: 'Purge cache' }).click();
  await confirm.getByRole('button', { name: 'Purge', exact: true }).click();
  await expect(page.getByText('Cache purged.')).toBeVisible();
  const purge = calls.find(call => call.path === '/v1/cache/purge' && call.method === 'POST');
  expect(purge.headers.authorization).toBe('Bearer correct-token');
  expect(cacheReads).toBeGreaterThanOrEqual(2);
});

test('cache policy uses the latest full config and invalid JSON cannot publish a stale value', async ({ page }) => {
  const enabled = { memory: { max_bytes: 33554432, max_entries: 4000, eviction: 'fifo' }, disk: null, max_object_bytes: 524288, max_fills: 16, fill_timeout_ms: 3000 };
  let activeConfig = config;
  const calls = await fixtures(page, {
    '/v1/config': route => {
      if (route.request().method() === 'PUT') {
        const body = JSON.parse(route.request().postData());
        activeConfig = { ...body, revision: 8 };
        return route.fulfill({ json: activeConfig, headers: { etag: '"8"' } });
      }
      return route.fulfill({ json: activeConfig, headers: { etag: `"${activeConfig.revision}"` } });
    },
    '/v1/cache': route => route.fulfill({ json: { enabled: true, config: enabled, stats: { memory_bytes: 0, memory_entries: 0, disk_bytes: 0, disk_entries: 0, hits: 0, misses: 0, evictions: 0, errors: 0 }, active_fills: 0 } }),
  });
  await login(page); await page.getByRole('link', { name: 'Cache', exact: true }).click();
  const editor = page.getByLabel('Global cache policy JSON');
  await editor.fill('{ broken');
  await page.getByRole('button', { name: 'Apply cache policy' }).click();
  await expect(page.locator('#cache-message')).toContainText('Invalid cache policy JSON');
  expect(calls.filter(call => call.path === '/v1/config' && call.method === 'PUT')).toHaveLength(0);

  await page.getByRole('button', { name: 'Insert template' }).click();
  await expect(editor).toHaveValue(/"max_fills": 32/);
  await editor.fill(JSON.stringify(enabled));
  await page.getByRole('button', { name: 'Apply cache policy' }).click();
  await expect(page.locator('#cache-message')).toContainText('revision 8');
  const update = calls.find(call => call.path === '/v1/config' && call.method === 'PUT');
  expect(update.headers['if-match']).toBe('"7"');
  expect(JSON.parse(update.body)).toMatchObject({ revision: 7, cache: enabled, http: config.http, tcp: config.tcp });
  await page.getByRole('link', { name: 'Configuration' }).click();
  await expect(page.getByLabel('JSON document')).toHaveValue(/"cache"/);
});

test('a late cache load cannot replace a newly edited policy draft', async ({ page }) => {
  const oldPolicy = { memory: { max_bytes: 1048576, max_entries: 64, eviction: 'lru' }, disk: null, max_object_bytes: 262144, max_fills: 4, fill_timeout_ms: 1000 };
  let activeConfig = { ...config, cache: oldPolicy };
  let releaseLoad;
  const loadGate = new Promise(resolve => { releaseLoad = resolve; });
  let holdNextLoad = false;
  let held = false;
  const calls = await fixtures(page, {
    '/v1/config': async route => {
      if (route.request().method() === 'PUT') {
        activeConfig = { ...route.request().postDataJSON(), revision: 8 };
        return route.fulfill({ json: activeConfig, headers: { etag: '"8"' } });
      }
      if (holdNextLoad && !held) { held = true; await loadGate; }
      return route.fulfill({ json: activeConfig, headers: { etag: `"${activeConfig.revision}"` } });
    },
    '/v1/cache': route => route.fulfill({ json: { enabled: activeConfig.cache !== null, config: activeConfig.cache, stats: null, active_fills: 0 } }),
  });
  await login(page);
  await page.getByRole('link', { name: 'Cache', exact: true }).click();
  await expect(page.getByLabel('Global cache policy JSON')).toHaveValue(/max_bytes/);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  holdNextLoad = true;
  await page.getByRole('link', { name: 'Cache', exact: true }).click();
  await expect.poll(() => held).toBe(true);
  const editor = page.getByLabel('Global cache policy JSON');
  await editor.fill('null');
  releaseLoad();
  await expect(editor).toHaveValue('null');
  await expect(page.locator('#cache-policy-dirty')).toBeVisible();
  await page.getByRole('button', { name: 'Apply cache policy' }).click();
  await expect(page.locator('#cache-message')).toContainText('revision 8');
  const write = calls.find(call => call.path === '/v1/config' && call.method === 'PUT');
  expect(JSON.parse(write.body).cache).toBeNull();
  await expect(page.locator('#cache-state')).toHaveText('Disabled');
});

test('certificate editor publishes file paths through the latest full config and rejects PEM fields', async ({ page }) => {
  let activeConfig = config;
  const calls = await fixtures(page, { '/v1/config': route => {
    if (route.request().method() === 'PUT') {
      const body = JSON.parse(route.request().postData());
      activeConfig = { ...body, revision: 8 };
      return route.fulfill({ json: activeConfig, headers: { etag: '"8"' } });
    }
    return route.fulfill({ json: activeConfig, headers: { etag: `"${activeConfig.revision}"` } });
  } });
  await login(page); await page.getByRole('link', { name: 'Certificates' }).click();
  const editor = page.getByLabel('Certificate set JSON');
  await expect(editor).toHaveValue('[]');
  await editor.fill(JSON.stringify([{ id: 'site', hosts: ['site.example.test'], cert_pem: '-----BEGIN CERTIFICATE-----', key_file: '/run/secrets/site.key' }]));
  await page.getByRole('button', { name: 'Apply certificates' }).click();
  await expect(page.locator('#certificate-message')).toContainText('unsupported field');
  expect(calls.filter(call => call.path === '/v1/config' && call.method === 'PUT')).toHaveLength(0);

  const certificates = [{ id: 'site', hosts: ['site.example.test', '*.site.example.test'], cert_file: '/run/secrets/site.crt', key_file: '/run/secrets/site.key' }];
  await editor.fill(JSON.stringify(certificates));
  await page.getByRole('button', { name: 'Apply certificates' }).click();
  await expect(page.locator('#certificate-message')).toContainText('revision 8');
  const update = calls.find(call => call.path === '/v1/config' && call.method === 'PUT');
  const body = JSON.parse(update.body);
  expect(update.headers['if-match']).toBe('"7"');
  expect(body).toMatchObject({ revision: 7, certificates, http: config.http, tcp: config.tcp });
  expect(update.body).not.toContain('BEGIN CERTIFICATE');
  expect(update.body).not.toContain('cert_pem');
  await expect(page.getByRole('heading', { name: 'site' })).toBeVisible();
});

test('certificate editor preserves default and issuer manifest on unchanged apply', async ({ page }) => {
  const registered = { id: 'managed-fixture', hosts: [], default: true, cert_file: '/run/certs/default.crt', key_file: '/run/certs/default.key', issuer_status_file: '/run/certs/issuer-status.json' };
  let activeConfig = { ...config, certificates: [registered] };
  const calls = await fixtures(page, { '/v1/config': route => {
    if (route.request().method() === 'PUT') {
      activeConfig = { ...JSON.parse(route.request().postData()), revision: 8 };
      return route.fulfill({ json: activeConfig, headers: { etag: '"8"' } });
    }
    return route.fulfill({ json: activeConfig, headers: { etag: `"${activeConfig.revision}"` } });
  } });
  await login(page); await page.getByRole('link', { name: 'Certificates' }).click();
  await expect(page.locator('#certificate-editor')).toHaveValue(JSON.stringify([registered], null, 2));
  await page.locator('#format-certificates').click();
  await page.getByRole('button', { name: 'Apply certificates' }).click();
  await expect(page.locator('#certificate-message')).toContainText('revision 8');
  expect(JSON.parse(calls.find(call => call.path === '/v1/config' && call.method === 'PUT').body).certificates).toEqual([registered]);
});

test('certificate inventory separates verified ACME reports, unknown issuers, and unreadable files without losing drafts', async ({ page }) => {
  const now = Date.UTC(2026, 8, 12);
  const manual = (index) => ({ id: `manual-${index}`, configured_hosts: [`host-${index}.example.test`], default: false, enabled: true, source: 'configured_file', read_state: 'ok', san_dns: [`host-${index}.example.test`], issuer: 'Example CA', not_before_unix_ms: now - 86400000, not_after_unix_ms: now + 90 * 86400000, fingerprint_sha256: 'a'.repeat(64), tls_binding: 'unknown', renewal: null });
  await fixtures(page, {
    '/v1/certificates': route => {
      const offset = Number(new URL(route.request().url()).searchParams.get('offset'));
      const first = { id: 'acme-site', configured_hosts: ['site.example.test'], default: true, enabled: true, source: 'standalone_acme', read_state: 'ok', san_dns: ['site.example.test', 'www.site.example.test'], issuer: 'Example ACME CA', not_before_unix_ms: now - 86400000, not_after_unix_ms: now + 20 * 86400000, fingerprint_sha256: 'b'.repeat(64), tls_binding: 'configured', renewal: { state: 'retrying', challenge: 'dns-01', checked_at_unix_ms: now, retry_next_unix_ms: now + 3600000 } };
      const bad = { ...manual(32), read_state: 'invalid', san_dns: [], issuer: null, not_after_unix_ms: null, tls_binding: 'unknown' };
      return route.fulfill({ json: { revision: 7, mode: 'configured_files', total: 33, offset, limit: 32, server_time_unix_ms: now, certificates: offset ? [bad] : [first, ...Array.from({ length: 31 }, (_, index) => manual(index + 1))], in_process_acme: { enabled: true, domains: ['site.example.test'], expires_unix_ms: now + 20 * 86400000, phase: 'issued', tls_available: false } } });
    },
  });
  await login(page);
  await page.getByRole('link', { name: 'Certificates' }).click();
  const inventory = page.locator('#certificate-inventory');
  await expect(inventory).toContainText('ACME-managed file references (1)');
  await expect(inventory).toContainText('Manually configured files · issuer unverified (31)');
  await expect(inventory).toContainText('Expires within 30 days');
  await expect(inventory).toContainText('Issuer-reported: retrying');
  await expect(inventory).toContainText('No verified renewal report');
  await expect(page.locator('#certificate-acme-state')).toContainText('In-process TLS available');
  const editor = page.getByLabel('Certificate set JSON');
  await editor.fill('[{"draft":true}]');
  await page.locator('#certificate-inventory-pages').getByRole('button', { name: 'Next' }).click();
  await expect(inventory).toContainText('Unreadable or invalid (1)');
  await expect(page.locator('#certificate-editor')).toHaveValue('[{"draft":true}]');
  await page.locator('#locale-select').selectOption('ko');
  await expect(inventory).toContainText('읽기 불가 또는 유효하지 않음');
  await expect(page.locator('#certificate-editor')).toHaveValue('[{"draft":true}]');
});

test('certificate inventory refreshes only while its view is visible and stops after logout', async ({ page }) => {
  await page.clock.install();
  let reads = 0;
  await fixtures(page, {
    '/v1/certificates': route => {
      reads += 1;
      return route.fulfill({ json: { revision: 7, mode: 'other_or_none', total: 0, offset: 0, limit: 32, server_time_unix_ms: Date.UTC(2026, 8, 12) + reads * 30000, certificates: [], in_process_acme: null } });
    },
  });
  await login(page);
  await page.getByRole('link', { name: 'Certificates' }).click();
  await expect.poll(() => reads).toBe(1);
  await page.clock.fastForward(30000);
  await expect.poll(() => reads).toBe(2);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await expect(page.locator('#view-http')).toBeVisible();
  await page.clock.fastForward(30000);
  expect(reads).toBe(2);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await page.clock.fastForward(30000);
  expect(reads).toBe(2);
});

test('route activation uses fresh CAS documents and keeps every other policy field', async ({ page }) => {
  let revision = 7;
  const routes = { http: [{ ...config.http[0], auth: { url: 'https://auth.example.test/check', request_headers: [], response_headers: [], timeout_ms: 1000 }, response_set_headers: { 'x-policy': 'keep' } }], tcp: [{ ...config.tcp[0], max_connections: 17 }] };
  const writes = [];
  let rejectNext = false;
  const overrides = {};
  for (const type of ['http', 'tcp']) {
    overrides[`/v1/routes/${type}`] = route => route.fulfill({ json: { revision, routes: routes[type] }, headers: { etag: `"${revision}"` } });
    const id = routes[type][0].id;
    overrides[`/v1/routes/${type}/${id}`] = route => {
      if (route.request().method() === 'GET') return route.fulfill({ json: routes[type][0], headers: { etag: `"${revision}"` } });
      if (rejectNext) { rejectNext = false; revision += 1; return route.fulfill({ status: 409, contentType: 'application/problem+json', json: { title: 'Revision Conflict', detail: 'revision changed', status: 409 } }); }
      const body = route.request().postDataJSON();
      writes.push({ type, body, ifMatch: route.request().headers()['if-match'] });
      routes[type][0] = body; revision += 1;
      return route.fulfill({ json: { ...body, revision }, headers: { etag: `"${revision}"` } });
    };
  }
  await fixtures(page, overrides);
  await login(page);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.locator('#http-routes tr[data-route-id="api"]').getByRole('button', { name: 'Deactivate' }).click();
  await expect(page.locator('#http-routes tr[data-route-id="api"]')).toContainText('Disabled');
  expect(writes[0]).toMatchObject({ type: 'http', ifMatch: '"7"', body: { enabled: false, auth: routes.http[0].auth, response_set_headers: { 'x-policy': 'keep' } } });
  await page.locator('#http-routes tr[data-route-id="api"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Route enabled')).not.toBeChecked();
  await page.getByLabel('Route enabled').check();
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.getByText('api updated.')).toBeVisible();
  expect(writes[1].body).not.toHaveProperty('enabled');
  await page.getByRole('link', { name: 'TCP routes' }).click();
  await page.locator('#tcp-routes tr[data-route-id="db"]').getByRole('button', { name: 'Deactivate' }).click();
  await expect(page.locator('#tcp-routes tr[data-route-id="db"]')).toContainText('Disabled');
  expect(writes[2]).toMatchObject({ type: 'tcp', body: { enabled: false, max_connections: 17 } });
  rejectNext = true;
  await page.locator('#tcp-routes tr[data-route-id="db"]').getByRole('button', { name: 'Activate' }).click();
  await expect(page.locator('#global-alert')).toContainText('route changed on the server');
  await expect(page.locator('#tcp-routes tr[data-route-id="db"]')).toContainText('Disabled');
  expect(writes).toHaveLength(3);
});

test('cache and certificate activation preserve their configured policies and reject dirty drafts', async ({ page }) => {
  let revision = 7;
  let active = { ...config, cache: { memory: { max_bytes: 1048576, max_entries: 64, eviction: 'lru' }, disk: null, max_object_bytes: 262144, max_fills: 4, fill_timeout_ms: 1000 }, certificates: [{ id: 'site', hosts: ['site.example.test'], cert_file: '/owned/site.crt', key_file: '/owned/site.key' }] };
  const writes = [];
  await fixtures(page, {
    '/v1/config': route => {
      if (route.request().method() === 'PUT') {
        writes.push({ body: route.request().postDataJSON(), ifMatch: route.request().headers()['if-match'] });
        active = { ...route.request().postDataJSON(), revision: ++revision };
      }
      return route.fulfill({ json: active, headers: { etag: `"${revision}"` } });
    },
    '/v1/cache': route => route.fulfill({ json: { enabled: active.cache?.enabled !== false, config: active.cache, stats: null, active_fills: 0 } }),
  });
  await login(page);
  await page.getByRole('link', { name: 'Cache', exact: true }).click();
  await expect(page.locator('#toggle-cache-policy')).toHaveText('Deactivate cache');
  await page.locator('#toggle-cache-policy').click();
  await expect(page.locator('#cache-state')).toHaveText('Disabled');
  expect(writes[0]).toMatchObject({ ifMatch: '"7"', body: { cache: { enabled: false, memory: active.cache.memory }, certificates: active.certificates, http: config.http, tcp: config.tcp } });
  await expect(page.getByLabel('Global cache policy JSON')).toHaveValue(/"enabled": false/);
  await page.getByLabel('Global cache policy JSON').fill('null');
  await page.locator('#toggle-cache-policy').click();
  expect(writes).toHaveLength(1);
  await expect(page.locator('#cache-message')).toContainText('unsaved');
  await page.getByRole('link', { name: 'Certificates' }).click();
  const list = page.locator('#certificate-list');
  await expect(list).toContainText('site');
  await list.getByRole('button', { name: 'Deactivate' }).click();
  await expect(list).toContainText('Disabled');
  expect(writes[1]).toMatchObject({ body: { certificates: [{ id: 'site', enabled: false, cert_file: '/owned/site.crt' }], cache: { enabled: false } } });
  await list.getByRole('button', { name: 'Activate' }).click();
  await expect.poll(() => writes.length).toBe(3);
  expect(writes[2].body.certificates[0]).not.toHaveProperty('enabled');
});

test('edits route cache TTLs and never submits an invalid native cache draft', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async route => {
    if (route.request().method() === 'POST') return route.fulfill({ status: 201, json: { id: 'cached', revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('cached');
  await openSection(page, 'Cache');
  await page.locator('input[name="cache_ttl_seconds"]').fill('30');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-message')).toContainText('cache TTL');
  expect(calls.filter(call => call.path === '/v1/routes/http' && call.method === 'POST')).toHaveLength(0);

  await page.locator('input[name="cache_max_ttl_seconds"]').fill('300');
  await page.getByRole('button', { name: 'Create route' }).click();
  const create = calls.find(call => call.path === '/v1/routes/http' && call.method === 'POST');
  expect(JSON.parse(create.body).cache).toEqual({ ttl_seconds: 30, max_ttl_seconds: 300 });
});

test('editing native fields preserves advanced route properties and refreshes the route from the server', async ({ page }) => {
  const auth = { url: 'http://auth.internal/check', request_headers: ['x-user'], response_headers: ['x-role'], timeout_ms: 900 };
  const listedRoute = { ...config.http[0], auth };
  // The single-route endpoint returns a newer document than the list: the editor must show it.
  const freshRoute = { ...listedRoute, future_field: { keep: true }, max_requests: 5 };
  const calls = await fixtures(page, {
    '/v1/routes/http': (route) => route.fulfill({ json: { revision: 7, routes: [listedRoute] }, headers: { etag: '"7"' } }),
    '/v1/routes/http/api': (route) => route.fulfill({ json: freshRoute, headers: { etag: '"8"' } }),
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Route ID')).not.toBeEditable();
  await expect(page.getByLabel('Concurrent request limit')).toHaveValue('5');
  await expect(sectionByTitle(page, 'External authorization')).toHaveJSProperty('open', true);
  await expect(page.getByLabel('Authorization URL')).toHaveValue('http://auth.internal/check');
  await page.getByLabel('Path prefix').fill('/api/'); await page.getByRole('button', { name: 'Save route' }).click();
  const update = calls.find((call) => call.path === '/v1/routes/http/api' && call.method === 'PUT');
  expect(update.headers['if-match']).toBe('"8"');
  expect(JSON.parse(update.body)).toMatchObject({ id: 'api', path_prefix: '/api/', max_requests: 5, auth: { ...auth, forward_response: false }, future_field: { keep: true } });
});

test('TCP route SNI, limits and upstream TLS use native controls and an invalid draft is never submitted', async ({ page }) => {
  const tcpRoute = { ...config.tcp[0], max_connections: 77, priority: 3 };
  const calls = await fixtures(page, {
    '/v1/routes/tcp': route => route.fulfill({ json: { revision: 7, routes: [tcpRoute] }, headers: { etag: '"7"' } }),
    '/v1/routes/tcp/db': route => route.fulfill({ json: tcpRoute, headers: { etag: '"8"' } }),
  });
  await login(page); await page.getByRole('link', { name: 'TCP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Concurrent connection limit')).toHaveValue('77');
  await expect(page.getByLabel('Matching priority')).toHaveValue('3');
  await expect(page.getByRole('button', { name: 'Resolve Docker backend…' })).toBeVisible();
  await openSection(page, 'TLS SNI routing');
  await page.getByLabel('ClientHello timeout (ms)').fill('3000');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(routeWrites(calls, '/v1/routes/tcp/db', 'PUT')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('at least one SNI hostname');

  await page.getByLabel('SNI hostname patterns').fill('db.example.test\n*.tenant.example.test');
  await page.getByLabel('SNI hostname regexes').fill('^db[0-9]+[.]example[.]test$');
  await page.getByLabel('Denied CIDRs').fill('2001:db8::/32');
  await openSection(page, 'Upstream connection');
  await page.getByLabel('Enable TLS to the upstream').check();
  await page.getByLabel('TLS server name').fill('db.internal');
  await page.getByLabel('TLS CA file').fill('/etc/hangang/ca.pem');
  await page.getByRole('button', { name: 'Save route' }).click();
  const update = calls.find(call => call.path === '/v1/routes/tcp/db' && call.method === 'PUT');
  expect(JSON.parse(update.body)).toMatchObject({
    id: 'db', priority: 3, max_connections: 77, listen: tcpRoute.listen, backends: tcpRoute.backends, deny_cidrs: ['2001:db8::/32'],
    sni: { hosts: ['db.example.test', '*.tenant.example.test'], host_regexes: ['^db[0-9]+[.]example[.]test$'], max_client_hello_bytes: 65536, hello_timeout_ms: 3000 },
    upstream: { connect_address: null, dns_servers: [], socks5: null, tls: { server_name: 'db.internal', insecure_skip_verify: false, ca_file: '/etc/hangang/ca.pem', max_fragment_size: null } },
  });
});

test('renders backend strings as text and browses OpenAPI operations', async ({ page }) => {
  await fixtures(page, { '/v1/routes/http': (route) => route.fulfill({ json: { revision: 7, routes: [{ ...config.http[0], id: '<img src=x onerror=window.pwned=true>' }] } }) });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await expect(page.getByText('<img src=x onerror=window.pwned=true>')).toBeVisible();
  expect(await page.evaluate(() => window.pwned)).toBeUndefined();
  await page.getByRole('link', { name: 'API reference' }).click();
  await expect(page.getByRole('heading', { name: /GET \/v1\/status/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Status', exact: true })).toBeVisible();
});

test('logout clears authorization, scrubs rendered configuration and returns to blocking login', async ({ page }) => {
  await fixtures(page); await login(page);
  await page.getByRole('link', { name: 'Configuration' }).click();
  await expect(page.getByLabel('JSON document')).toHaveValue(/127\.0\.0\.1:8080/);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await expect(page.getByRole('heading', { name: 'api' })).toBeVisible();
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('dialog', { name: 'Connect to this proxy' })).toBeVisible();
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage), cookie: document.cookie }))).toEqual({ local: [], session: [], cookie: '' });
  const leftovers = await page.evaluate(() => ({
    editors: ['#config-editor', '#cache-policy-editor', '#certificate-editor', '#route-json'].map((id) => document.querySelector(id).value),
    routes: document.querySelector('#http-routes').childElementCount + document.querySelector('#tcp-routes').childElementCount,
    metrics: document.querySelector('#metric-grid').childElementCount,
    text: document.body.textContent,
  }));
  expect(leftovers.editors).toEqual(['', '', '', '']);
  expect(leftovers.routes).toBe(0);
  expect(leftovers.metrics).toBe(0);
  expect(leftovers.text).not.toContain('127.0.0.1:8080');
  expect(leftovers.text).not.toContain('1,284');
});

test('supervised restart and signed update controls confirm before calling authenticated endpoints', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/status': route => route.fulfill({ json: { ...status, state: { draining: false, supervised: true } } }),
    '/v1/update/status': route => route.fulfill({ json: { enabled: true, phase: 'idle', current_version: '0.1.0', last_check_unix: 0, detail: null } }),
    '/v1/lifecycle/restart': route => route.fulfill({ status: 202, json: { accepted: true } }),
    '/v1/update/check': route => route.fulfill({ status: 202, json: { accepted: true } }),
  });
  await login(page);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByRole('button', { name: 'Graceful restart' }).click();
  const restart = page.getByRole('dialog', { name: 'Restart the proxy?' });
  await expect(restart).toBeVisible();
  await restart.getByRole('button', { name: 'Cancel' }).click();
  expect(calls.filter(call => call.path === '/v1/lifecycle/restart')).toHaveLength(0);
  await page.getByRole('button', { name: 'Graceful restart' }).click();
  await restart.getByRole('button', { name: 'Restart', exact: true }).click();
  await expect(page.getByText('Restart requested. Existing connections will drain.')).toBeVisible();
  await page.getByRole('button', { name: 'Check and apply update' }).click();
  const update = page.getByRole('dialog', { name: 'Check for a signed update?' });
  await expect(update).toBeVisible();
  await update.getByRole('button', { name: 'Check and apply', exact: true }).click();
  await expect(page.getByText('Signed update check requested.')).toBeVisible();
  for (const path of ['/v1/lifecycle/restart', '/v1/update/check']) {
    expect(calls.filter(call => call.path === path && call.method === 'POST')).toHaveLength(1);
    expect(calls.find(call => call.path === path && call.method === 'POST')?.headers.authorization).toBe('Bearer correct-token');
  }
});

test('diagnostics reach the authenticated health and Prometheus endpoints', async ({ page }) => {
  const calls = await fixtures(page);
  await login(page);
  await page.getByRole('button', { name: 'Check health' }).click();
  await expect(page.locator('#health-result')).toContainText('Healthy · ok');
  await page.getByRole('button', { name: 'Load Prometheus metrics' }).click();
  await expect(page.locator('#metrics-output')).toContainText('hangang_requests_total 1284');
  for (const path of ['/healthz', '/metrics']) expect(calls.find(call => call.path === path)?.headers.authorization).toBe('Bearer correct-token');
});

test('shows automatic certificate state and controller readiness', async ({ page }) => {
  await fixtures(page, {'/v1/status': route => route.fulfill({json: {...status, state: {ready:false, configuration_source:'kubernetes'}, acme: {enabled:true, phase:'retrying', domains:['app.example.test'], expires_unix:2000000000}}})});
  await login(page);
  await expect(page.locator('#configuration-source')).toHaveText('kubernetes');
  await expect(page.locator('#runtime-state')).toHaveText('Waiting for configuration');
  await expect(page.locator('#acme-state')).toHaveText('retrying');
  await expect(page.locator('#acme-detail')).toContainText('app.example.test');
  await expect(page.locator('#acme-detail')).toContainText('Expires');
});

test('edits bounded request and response transformations with native controls and preserves Lua source', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/routes/http/api': route => route.fulfill({ json: config.http[0], headers: { etag: '"8"' } }),
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await openSection(page, 'Request body transform');
  await expect(page.getByLabel('Request transform mode')).toBeDisabled();
  await page.getByLabel('Enable request body transform').check();
  await expect(page.getByLabel('Request transform mode')).toBeEnabled();
  await page.getByLabel('Request transform operations').fill(JSON.stringify([{ op: 'json_remove', pointer: '/secret' }]));
  await page.getByLabel('Request transform buffer limit').fill('4096');
  await openSection(page, 'Response body transform');
  await page.getByLabel('Enable response body transform').check();
  await page.getByLabel('Response transform mode').selectOption('sse');
  await page.getByRole('textbox', { name: 'Response transform Lua' }).fill('return hangang.body()\n-- "quoted"');
  await page.getByLabel('Response transform buffer limit').fill('16384');
  await page.getByLabel('Response transform output limit').fill('16384');
  await page.getByLabel('Response transform set headers').fill('x-transformed: yes');
  await page.getByLabel('Response transform remove headers').fill('x-internal');
  await page.getByLabel('Path prefix').fill('/stream');
  await page.getByRole('button', { name: 'Save route' }).click();
  const update = calls.find(call => call.path === '/v1/routes/http/api' && call.method === 'PUT');
  expect(JSON.parse(update.body)).toMatchObject({
    path_prefix: '/stream',
    request_transform: { mode: 'buffered', operations: [{ op: 'json_remove', pointer: '/secret' }], lua: null, max_buffer_bytes: 4096, max_output_bytes: 65536, timeout_ms: 5000, set_headers: {}, remove_headers: [] },
    response_transform: { mode: 'sse', operations: [], lua: 'return hangang.body()\n-- "quoted"', max_buffer_bytes: 16384, max_output_bytes: 16384, timeout_ms: 5000, set_headers: { 'x-transformed': 'yes' }, remove_headers: ['x-internal'] },
  });
});

test('invalid transformation operations cannot silently submit the last valid draft', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http/api': route => route.fulfill({ json: config.http[0], headers: { etag: '"8"' } }) });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await openSection(page, 'Response body transform');
  await page.getByLabel('Enable response body transform').check();
  await page.getByLabel('Response transform operations').fill('{ broken');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(calls.filter(call => call.method === 'PUT')).toHaveLength(0);
  await expect(page.locator('#route-dialog')).toBeVisible();
  await expect(page.locator('#route-message')).toContainText('operations is not valid JSON');
  await page.getByLabel('Response transform operations').fill('');
  await page.getByLabel('Response transform mode').selectOption('lines');
  const refreshedRoutes = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/routes/http' && response.request().method() === 'GET');
  await page.getByRole('button', { name: 'Save route' }).click();
  await refreshedRoutes;
  await expect(page.getByRole('button', { name: 'Edit' })).toBeVisible();
  const update = calls.find(call => call.path === '/v1/routes/http/api' && call.method === 'PUT');
  expect(JSON.parse(update.body).response_transform).toMatchObject({ mode: 'lines', operations: [] });
  // Unchecking the transform removes it entirely instead of leaving stale fields behind.
  const populated = { ...config.http[0], response_transform: { mode: 'ndjson', operations: [], lua: null, max_buffer_bytes: 65536, max_output_bytes: 65536, timeout_ms: 5000, set_headers: {}, remove_headers: [] } };
  await page.unroute('**/*');
  const second = await fixtures(page, { '/v1/routes/http/api': route => route.fulfill({ json: populated, headers: { etag: '"9"' } }), '/v1/routes/http': route => route.fulfill({ json: { revision: 9, routes: [populated] }, headers: { etag: '"9"' } }) });
  await page.getByRole('link', { name: 'HTTP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Enable response body transform')).toBeChecked();
  await page.getByLabel('Enable response body transform').uncheck();
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(JSON.parse(second.find(call => call.method === 'PUT').body).response_transform).toBeNull();
});

test('upstream connection policy and Host survive route editing with invalid-draft protection', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ json: { ...status, revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('outbound');
  await page.getByLabel('Backends').fill('http://logical.example');
  await page.getByLabel('Upstream Host override').fill('foo.bar');
  await openSection(page, 'Upstream connection');
  await page.getByLabel('Connect address').fill('192.0.2.4:443');
  await page.getByLabel('Upstream DNS servers').fill('192.0.2.53:53');
  await page.getByLabel('SOCKS5 proxy address').fill('127.0.0.1:1080');
  await page.getByLabel('SOCKS5 username variable').fill('HANGANG_SOCKS5_USER');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('configured together');
  await page.getByLabel('SOCKS5 password variable').fill('HANGANG_SOCKS5_PASSWORD');
  await page.getByLabel('Configure upstream TLS verification').check();
  await page.getByLabel('TLS server name').fill('foo.bar');
  await page.getByLabel('Skip TLS certificate verification').check();
  await page.getByLabel('TLS maximum fragment size').fill('128');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('https://');
  await page.getByLabel('Backends').fill('https://logical.example');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('outbound created.')).toBeVisible();
  const options = { connect_address: '192.0.2.4:443', dns_servers: ['192.0.2.53:53'], socks5: { address: '127.0.0.1:1080', username_env: 'HANGANG_SOCKS5_USER', password_env: 'HANGANG_SOCKS5_PASSWORD' }, tls: { server_name: 'foo.bar', insecure_skip_verify: true, ca_file: null, max_fragment_size: 128 } };
  const call = calls.find(c => c.path === '/v1/routes/http' && c.method === 'POST');
  expect(JSON.parse(call.body)).toMatchObject({ upstream: options, upstream_host: 'foo.bar', preserve_host: false });
});

test('Unix upstream socket is shown for HTTP and TCP and conflicts fail before publication', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ status: 201, json: { id: 'relay', revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('relay');
  await page.getByLabel('Backends').fill('https://logical.example');
  await openSection(page, 'Upstream connection');
  await page.getByLabel('Unix socket').fill('/run/hangang/egress.sock');
  await page.getByLabel('Connect address').fill('127.0.0.1:8443');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('cannot be combined');
  await page.getByLabel('Connect address').fill('');
  await page.getByLabel('Unix socket').fill('/run/../egress.sock');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('normalized path');
  await page.getByLabel('Unix socket').fill('/run/hangang/egress.sock');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('relay created.')).toBeVisible();
  expect(JSON.parse(routeWrites(calls, '/v1/routes/http', 'POST')[0].body)).toMatchObject({
    backends: ['https://logical.example'], upstream: { unix_socket: '/run/hangang/egress.sock', connect_address: null, dns_servers: [], socks5: null },
  });
  await page.getByRole('link', { name: 'TCP routes' }).click();
  await page.getByRole('button', { name: 'New TCP route' }).click();
  await openSection(page, 'Upstream connection');
  await expect(page.getByLabel('Unix socket')).toBeVisible();
});

test('host match modes preserve drafts, and matching priority and Host conflicts are explicit', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ json: { ...status, revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('regex-route');
  await page.getByLabel('Host match').fill('f??.bar.com');
  await page.getByLabel('Host selection mode').selectOption('regex');
  await page.getByLabel('Host regular expression').fill('f[a-z]{2}[.]bar[.]com');
  await page.getByLabel('Host selection mode').selectOption('single');
  await expect(page.getByLabel('Host match')).toHaveValue('f??.bar.com');
  await page.getByLabel('Host selection mode').selectOption('regex');
  await expect(page.getByLabel('Host regular expression')).toHaveValue('f[a-z]{2}[.]bar[.]com');
  await page.getByLabel('Matching priority').fill('42');
  await page.getByLabel('Path match mode').selectOption('segment_prefix');
  await page.getByLabel('Preserve incoming Host').check();
  await page.getByLabel('Upstream Host override').fill('conflict.example');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(calls.filter(c => c.path === '/v1/routes/http' && c.method === 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('Preserve incoming Host conflicts');
  await page.getByLabel('Upstream Host override').fill('');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('regex-route created.')).toBeVisible();
  const posted = JSON.parse(calls.find(c => c.path === '/v1/routes/http' && c.method === 'POST').body);
  expect(posted).toMatchObject({ host: null, host_regex: 'f[a-z]{2}[.]bar[.]com', priority: 42, path_match: 'segment_prefix', preserve_host: true, upstream_host: null });
  expect(posted).not.toHaveProperty('hosts');
});

test('domain group saves one shared route and survives inventory search, locale and edit round-trip', async ({ page }) => {
  let saved = null;
  let revision = 7;
  const writes = [];
  await fixtures(page, {
    '/v1/routes/http': route => {
      const method = route.request().method();
      if (method === 'GET') return route.fulfill({ json: { revision, routes: saved ? [...config.http, saved] : config.http }, headers: { etag: `"${revision}"` } });
      saved = route.request().postDataJSON(); writes.push({ method, route: saved }); revision += 1;
      return route.fulfill({ status: 201, json: { ...saved, revision }, headers: { etag: `"${revision}"` } });
    },
    '/v1/routes/http/sites': route => {
      const method = route.request().method();
      if (method === 'GET') return route.fulfill({ json: saved, headers: { etag: `"${revision}"` } });
      saved = route.request().postDataJSON(); writes.push({ method, route: saved }); revision += 1;
      return route.fulfill({ json: saved, headers: { etag: `"${revision}"` } });
    },
  });
  await login(page);
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('sites');
  await page.getByLabel('Host selection mode').selectOption('group');
  await expect(page.locator('#route-message')).toContainText('Domain groups need 1–32 hosts');
  await page.getByLabel('Domain group hosts').fill('foo.com\nFOO.COM');
  await expect(page.locator('#route-message')).toContainText('distinct, ignoring case');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(writes).toHaveLength(0);
  await page.getByLabel('Domain group hosts').fill('foo.com\nwww.foo.com');
  await page.getByLabel('Backends').fill('https://app.internal:8443');
  await page.getByLabel('Require TLS').check();
  await page.getByLabel('Host selection mode').selectOption('single');
  await page.getByLabel('Host match').fill('temporary.example.test');
  await page.getByLabel('Host selection mode').selectOption('group');
  await expect(page.getByLabel('Domain group hosts')).toHaveValue('foo.com\nwww.foo.com');
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.getByLabel('도메인 그룹 호스트')).toHaveValue('foo.com\nwww.foo.com');
  await page.locator('#locale-select-route').selectOption('en');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('sites created.')).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].route).toMatchObject({
    id: 'sites', host: null, hosts: ['foo.com', 'www.foo.com'], host_regex: null,
    backends: ['https://app.internal:8443'], require_tls: true,
  });

  const inventory = page.locator('#http-routes');
  await inventory.locator('.route-policy-filter').selectOption('domains');
  await expect(inventory.locator('tbody tr')).toHaveCount(1);
  await expect(inventory.locator('tbody tr')).toContainText('foo.com, www.foo.com');
  await inventory.locator('.route-search').fill('www.foo.com');
  await expect(inventory.locator('tbody tr')).toHaveCount(1);
  await inventory.locator('tbody tr').getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Host selection mode')).toHaveValue('group');
  await expect(page.getByLabel('Domain group hosts')).toHaveValue('foo.com\nwww.foo.com');
  await expect(page.getByLabel('Backends')).toHaveValue('https://app.internal:8443');
  await expect(page.getByLabel('Require TLS')).toBeChecked();
  await page.getByLabel('Domain group hosts').fill('foo.com\nwww.foo.com\napi.foo.com');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.getByText('sites updated.')).toBeVisible();
  expect(writes[1]).toMatchObject({ method: 'PUT', route: { hosts: ['foo.com', 'www.foo.com', 'api.foo.com'], backends: ['https://app.internal:8443'], require_tls: true } });
  await inventory.locator('.route-search').fill('api.foo.com');
  await expect(inventory.locator('tbody tr')).toHaveCount(1);
  await expect(inventory.locator('tbody tr')).toContainText('+1 more hosts');
});

test('TLS requirement, timeouts, retries, response headers and balancing are native HTTP route controls', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ status: 201, json: { id: 'edge', revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('edge');
  await page.getByLabel('Backends').fill('http://10.0.0.2:8080\nhttp://10.0.0.3:8080');
  await page.getByLabel('Require TLS').check();
  await page.getByLabel('Upstream timeout (ms)').fill('120000');
  await page.getByLabel('Retries').fill('2');
  await page.getByLabel('Header matches').fill('x-tenant: acme');
  await page.getByLabel('JSON matches').fill('/kind = "order"');
  await openSection(page, 'Response headers');
  await page.getByLabel('Set response headers').fill('strict-transport-security: max-age=63072000\nx-frame-options: DENY');
  await page.getByLabel('Remove response headers').fill('server\nx-powered-by');
  await openSection(page, 'Load balancing');
  await page.getByLabel('Balancing mode').selectOption('least_connections');
  await page.getByLabel('Backend weights').fill('3');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('exactly 2 values');
  await page.getByLabel('Backend weights').fill('3, 1');
  await page.getByLabel('Failure threshold').fill('3');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('both a failure threshold and a cooldown');
  await page.getByLabel('Cooldown (ms)').fill('15000');
  await page.getByLabel('Retries').fill('40');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await page.getByLabel('Retries').fill('2');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('edge created.')).toBeVisible();
  expect(JSON.parse(routeWrites(calls, '/v1/routes/http', 'POST')[0].body)).toMatchObject({
    id: 'edge', require_tls: true, upstream_timeout_ms: 120000, retries: 2, headers: { 'x-tenant': 'acme' }, json: { '/kind': 'order' },
    response_set_headers: { 'strict-transport-security': 'max-age=63072000', 'x-frame-options': 'DENY' }, response_remove_headers: ['server', 'x-powered-by'],
    balance: { mode: 'least_connections', weights: [3, 1], health: { failure_threshold: 3, cooldown_ms: 15000 } },
  });
});

test('external and basic authentication are native controls with invalid-draft protection', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ status: 201, json: { id: 'secure', revision: 8 }, headers: { etag: '"8"' } });
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('secure');
  await openSection(page, 'External authorization');
  await page.getByLabel('Forwarded request headers').fill('cookie');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('needs an Authorization URL');
  await page.getByLabel('Authorization URL').fill('https://auth.internal/check');
  await page.getByLabel('Identity response headers').fill('x-user\nx-role');
  await page.getByLabel('Authorization timeout (ms)').fill('900');
  await page.getByLabel('Forward denial responses').check();
  await openSection(page, 'Basic authentication');
  await expect(sectionByTitle(page, 'Basic authentication')).toContainText('hangang --hash-password');
  await page.getByLabel('Credentials', { exact: true }).fill('alice:not-a-hash');
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('hangang --hash-password');
  await page.getByLabel('Credentials', { exact: true }).fill(`${CREDENTIAL}\n${CREDENTIAL}`);
  await page.getByRole('button', { name: 'Create route' }).click();
  expect(routeWrites(calls, '/v1/routes/http', 'POST')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('Duplicate basic-auth username');
  await page.getByLabel('Credentials', { exact: true }).fill(CREDENTIAL);
  await page.getByLabel('Realm').fill('ops');
  await page.getByLabel('Identity header', { exact: true }).fill('x-authenticated-user');
  await page.getByLabel('Hide credentials from the upstream').check();
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.getByText('secure created.')).toBeVisible();
  expect(JSON.parse(routeWrites(calls, '/v1/routes/http', 'POST')[0].body)).toMatchObject({
    auth: { url: 'https://auth.internal/check', request_headers: ['cookie'], response_headers: ['x-user', 'x-role'], timeout_ms: 900, forward_response: true },
    basic_auth: { realm: 'ops', credentials: [CREDENTIAL], hide_credentials: true, identity_header: 'x-authenticated-user' },
  });
});

test('populated authentication and header controls round-trip an existing route and can be disabled', async ({ page }) => {
  const populated = {
    ...config.http[0], require_tls: true, retries: 3, upstream_timeout_ms: 30000, path_match: 'exact',
    auth: { url: 'https://auth.internal/check', request_headers: ['cookie'], response_headers: ['x-user'], timeout_ms: 700, forward_response: true },
    basic_auth: { realm: 'ops', credentials: [CREDENTIAL], hide_credentials: true, identity_header: 'x-authenticated-user' },
    response_set_headers: { 'x-frame-options': 'DENY' }, response_remove_headers: ['server'],
    balance: { mode: 'least_connections', weights: [2], health: { failure_threshold: 2, cooldown_ms: 500 } },
  };
  const calls = await fixtures(page, {
    '/v1/routes/http': route => route.fulfill({ json: { revision: 7, routes: [populated] }, headers: { etag: '"7"' } }),
    '/v1/routes/http/api': route => route.fulfill({ json: populated, headers: { etag: '"7"' } }),
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await expect(page.locator('.route-card')).toContainText(['TLS required']);
  await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByLabel('Require TLS')).toBeChecked();
  await expect(page.getByLabel('Retries')).toHaveValue('3');
  await expect(page.getByLabel('Upstream timeout (ms)')).toHaveValue('30000');
  await expect(page.getByLabel('Path match mode')).toHaveValue('exact');
  for (const title of ['External authorization', 'Basic authentication', 'Response headers', 'Load balancing']) await expect(sectionByTitle(page, title)).toHaveJSProperty('open', true);
  await expect(page.getByLabel('Authorization URL')).toHaveValue('https://auth.internal/check');
  await expect(page.getByLabel('Forward denial responses')).toBeChecked();
  await expect(page.getByLabel('Credentials', { exact: true })).toHaveValue(CREDENTIAL);
  await expect(page.getByLabel('Realm')).toHaveValue('ops');
  await expect(page.getByLabel('Hide credentials from the upstream')).toBeChecked();
  await expect(page.getByLabel('Set response headers')).toHaveValue('x-frame-options: DENY');
  await expect(page.getByLabel('Remove response headers')).toHaveValue('server');
  await expect(page.getByLabel('Balancing mode')).toHaveValue('least_connections');
  await expect(page.getByLabel('Backend weights')).toHaveValue('2');
  await expect(page.getByLabel('Failure threshold')).toHaveValue('2');
  await expect(page.getByLabel('Cooldown (ms)')).toHaveValue('500');
  // Disable both authentication mechanisms: the key fields go blank, dependent fields are cleared too.
  await page.getByLabel('Authorization URL').fill('');
  await page.getByLabel('Forwarded request headers').fill('');
  await page.getByLabel('Identity response headers').fill('');
  await page.getByLabel('Authorization timeout (ms)').fill('');
  await page.getByLabel('Forward denial responses').uncheck();
  await page.getByLabel('Credentials', { exact: true }).fill('');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(routeWrites(calls, '/v1/routes/http/api', 'PUT')).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('clear the realm');
  await page.getByLabel('Realm').fill('');
  await page.getByLabel('Identity header', { exact: true }).fill('');
  await page.getByLabel('Hide credentials from the upstream').uncheck();
  await page.getByLabel('Require TLS').uncheck();
  await page.getByRole('button', { name: 'Save route' }).click();
  const update = routeWrites(calls, '/v1/routes/http/api', 'PUT')[0];
  expect(JSON.parse(update.body)).toMatchObject({ id: 'api', auth: null, basic_auth: null, require_tls: false, retries: 3, upstream_timeout_ms: 30000, path_match: 'exact', response_set_headers: { 'x-frame-options': 'DENY' }, balance: populated.balance });
});

test('a generic route 422 is explained with the validator detail for the merged document', async ({ page }) => {
  const calls = await fixtures(page, {
    '/v1/routes/http/api': route => route.request().method() === 'PUT'
      ? route.fulfill({ status: 422, contentType: 'application/problem+json', json: { type: 'about:blank', title: 'Configuration Rejected', status: 422, detail: 'configuration validation or activation failed; reload the current revision before retrying' } })
      : route.fulfill({ json: config.http[0], headers: { etag: '"7"' } }),
    '/v1/config/validate': route => route.fulfill({ status: 422, contentType: 'application/problem+json', json: { type: 'about:blank', title: 'Configuration Invalid', status: 422, detail: 'invalid upstream_host' } }),
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await page.getByLabel('Upstream Host override').fill('bad host');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-message')).toHaveText('invalid upstream_host');
  await expect(page.locator('#route-dialog')).toBeVisible();
  const validate = calls.find(call => call.path === '/v1/config/validate');
  const draft = JSON.parse(validate.body);
  expect(draft.http).toHaveLength(1);
  expect(draft.http[0]).toMatchObject({ id: 'api', upstream_host: 'bad host' });
  expect(draft.tcp).toEqual(config.tcp);
});

test('route id conflicts and stale revisions are reported without losing the draft', async ({ page }) => {
  let posts = 0;
  const calls = await fixtures(page, { '/v1/routes/http': async (route) => {
    if (route.request().method() === 'POST') { posts++; return route.fulfill({ status: 409, contentType: 'application/problem+json', json: { type: 'about:blank', title: 'Route Conflict', status: 409, detail: posts === 1 ? 'route id already exists' : 'revision conflict' } }); }
    return route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } });
  } });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route ID').fill('api');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-message')).toContainText('already exists');
  await expect(page.getByLabel('Route ID')).toHaveValue('api');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-message')).toContainText('configuration changed on the server');
  expect(calls.filter(call => call.path === '/v1/routes/http' && call.method === 'POST')).toHaveLength(2);
});

test('the advanced JSON editor remains authoritative for fields it introduces', async ({ page }) => {
  const calls = await fixtures(page, { '/v1/routes/tcp/db': route => route.fulfill({ json: config.tcp[0], headers: { etag: '"7"' } }) });
  await login(page); await page.getByRole('link', { name: 'TCP routes' }).click(); await page.getByRole('button', { name: 'Edit' }).click();
  await page.locator('details.advanced-editor summary').click();
  const editor = page.locator('#route-json');
  const current = JSON.parse(await editor.inputValue());
  await editor.fill(JSON.stringify({ ...current, experimental: { enabled: true } }));
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(JSON.parse(calls.find(call => call.method === 'PUT').body)).toMatchObject({ id: 'db', experimental: { enabled: true }, backends: config.tcp[0].backends });
});

const fleetStatus = {
  ...status,
  state: { draining: false, supervised: false, ready: true, configuration_source: 'shared' },
  instance: { id: '9f3a1c77d2e04b58', config_digest: '4d1f0b9a7c3e2a10' },
  settings: { trusted_proxy_cidrs: ['10.0.0.0/8', 'fd00::/8'], https_redirect_code: 301, allow_dot_segments: false },
  store: { epoch: '3a921a445a0d2b783d1c3a444af8b174', revision: 7, ready: true, degraded: true, reason: 'unavailable', detail: 'store unavailable: connection refused', last_confirmed_seconds_ago: 12, grace_seconds: 30 },
};

test('status page shows instance identity, shared-store health and fleet settings', async ({ page }) => {
  let served = fleetStatus;
  await fixtures(page, { '/v1/status': route => route.fulfill({ json: served }) });
  await login(page);
  await expect(page.locator('#instance-id')).toHaveText('9f3a1c77d2e04b58');
  await expect(page.locator('#instance-digest')).toHaveText('4d1f0b9a7c3e2a10');
  const panel = page.locator('#store-panel');
  await expect(panel).toBeVisible();
  await expect(page.locator('#store-state')).toHaveText('Degraded');
  await expect(page.locator('#store-reason')).toHaveText('unavailable');
  await expect(page.locator('#store-reason-help')).toContainText('tolerated for 30 s');
  await expect(page.locator('#store-confirmed')).toHaveText('confirmed 12 s ago');
  await expect(page.locator('#store-epoch')).toHaveText('3a921a445a0d2b783d1c3a444af8b174');
  await expect(page.locator('#store-detail')).toHaveText('store unavailable: connection refused');
  await expect(page.locator('#setting-active-trusted_proxy_cidrs')).toHaveText('10.0.0.0/8, fd00::/8');
  await expect(page.locator('#setting-active-https_redirect_code')).toHaveText('301');
  await expect(page.locator('#setting-active-allow_dot_segments')).toHaveText('Rejected');
  await expect(page.locator('#setting-active-health_path')).toHaveText('Process default');
  // Authority disagreement: withdrawn, explained as immediate.
  served = { ...fleetStatus, store: { ...fleetStatus.store, ready: false, degraded: false, reason: 'authority_changed', detail: 'store epoch differs', last_confirmed_seconds_ago: 90 } };
  await page.locator('#refresh-status').click();
  await expect(page.locator('#store-state')).toHaveText('Withdrawn');
  await expect(page.locator('#store-reason-help')).toContainText('withdrawn immediately');
  // File mode: no store block, panel hidden.
  served = { ...status, instance: fleetStatus.instance, settings: {}, store: null };
  await page.locator('#refresh-status').click();
  await expect(panel).toBeHidden();
  await expect(page.locator('#setting-active-https_redirect_code')).toHaveText('Process default');
});

test('fleet purge reports its scope and generation and advances the held revision', async ({ page }) => {
  const cacheConfig = { memory: { max_bytes: 67108864, max_entries: 10000, eviction: 'lru' }, disk: null, max_object_bytes: 1048576, max_fills: 32, fill_timeout_ms: 5000, generation: 3 };
  let generation = 3; let revision = 7;
  const calls = await fixtures(page, {
    '/v1/status': route => route.fulfill({ json: fleetStatus }),
    '/v1/cache': route => route.fulfill({ json: { enabled: true, config: cacheConfig, generation, stats: { memory_bytes: 0, memory_entries: 0, disk_bytes: 0, disk_entries: 0, hits: 0, misses: 0, evictions: 0, errors: 0 }, active_fills: 0 } }),
    '/v1/cache/purge': route => { generation += 1; revision += 1; return route.fulfill({ json: { purged: true, scope: 'fleet', generation, revision }, headers: { etag: `"${revision}"` } }); },
    '/v1/config': route => route.fulfill({ json: { ...config, revision, cache: { ...cacheConfig, generation } }, headers: { etag: `"${revision}"` } }),
  });
  await login(page); await page.getByRole('link', { name: 'Cache', exact: true }).click();
  await expect(page.locator('#cache-generation')).toHaveText('3');
  await expect(page.locator('#cache-purge-scope')).toHaveText('Fleet');
  await expect(page.getByLabel('Invalidation generation')).toHaveValue('3');
  await page.getByRole('button', { name: 'Purge cache' }).click();
  const confirm = page.getByRole('dialog', { name: 'Purge the cache fleet-wide?' });
  await expect(confirm).toContainText('cache.generation');
  await confirm.getByRole('button', { name: 'Purge', exact: true }).click();
  await expect(page.getByText('Fleet cache purge published.')).toBeVisible();
  await expect(page.locator('#cache-message')).toContainText('generation 4 in revision 8');
  await expect(page.locator('#cache-generation')).toHaveText('4');
  expect(calls.filter(call => call.path === '/v1/cache/purge' && call.method === 'POST')).toHaveLength(1);
  // The console re-based on revision 8: the next configuration write carries the new precondition.
  await page.getByRole('link', { name: 'Configuration' }).click();
  await expect(page.locator('#config-editor')).toHaveValue(/"generation": 4/);
});

test('fleet settings are edited natively and published inside the document', async ({ page }) => {
  const withSettings = { ...config, settings: { trusted_proxy_cidrs: ['10.0.0.0/8'], https_redirect_code: 308 } };
  const calls = await fixtures(page, {
    '/v1/config': route => route.request().method() === 'PUT'
      ? route.fulfill({ json: { ...JSON.parse(route.request().postData()), revision: 8 }, headers: { etag: '"8"' } })
      : route.fulfill({ json: withSettings, headers: { etag: '"7"' } }),
  });
  await login(page); await page.getByRole('link', { name: 'Configuration' }).click();
  await expect(page.getByLabel('Trusted proxy CIDRs')).toHaveValue('10.0.0.0/8');
  await expect(page.getByLabel('HTTPS redirect code')).toHaveValue('308');
  await expect(page.getByLabel('Health path')).toHaveValue('');
  await expect(page.locator('#settings-state')).toBeVisible();
  await page.getByLabel('Trusted proxy CIDRs').fill('10.0.0.0/8\n192.168.0.0/16');
  await page.getByLabel('Upstream timeout default (ms)').fill('120000');
  await page.getByLabel('Dot segments in request paths').selectOption('true');
  await page.getByLabel('Health path').fill('/-/ready');
  await page.getByLabel('HTTPS redirect code').selectOption('');
  await expect(page.locator('#config-editor')).toHaveValue(/"health_path": "\/-\/ready"/);
  await expect(page.locator('#config-editor')).not.toHaveValue(/https_redirect_code/);
  // A malformed value blocks publication with an explanation.
  await page.getByLabel('Health path').fill('ready');
  await page.getByRole('button', { name: 'Apply configuration' }).click();
  await expect(page.locator('#config-message')).toContainText(/health path|Fleet settings/i);
  expect(routeWrites(calls, '/v1/config', 'PUT')).toHaveLength(0);
  await page.getByLabel('Health path').fill('/-/ready');
  await page.getByRole('button', { name: 'Apply configuration' }).click();
  await expect(page.locator('#config-message')).toContainText(/revision 8/i);
  const put = routeWrites(calls, '/v1/config', 'PUT')[0];
  expect(put.headers['if-match']).toBe('"7"');
  expect(JSON.parse(put.body).settings).toEqual({ trusted_proxy_cidrs: ['10.0.0.0/8', '192.168.0.0/16'], upstream_timeout_ms: 120000, allow_dot_segments: true, health_path: '/-/ready' });
});

test('basic authentication credentials are generated through the hashing endpoint', async ({ page }) => {
  const populated = { ...config.http[0], basic_auth: { realm: 'ops', credentials: [CREDENTIAL], hide_credentials: false, identity_header: null } };
  const generated = `bob:${'12'.repeat(16)}:${'ef'.repeat(32)}`;
  const calls = await fixtures(page, {
    '/v1/routes/http': route => route.fulfill({ json: { revision: 7, routes: [populated] }, headers: { etag: '"7"' } }),
    '/v1/routes/http/api': route => route.fulfill({ json: populated, headers: { etag: '"7"' } }),
    '/v1/util/hash-password': route => {
      const body = JSON.parse(route.request().postData());
      if (body.username === 'reserved') return route.fulfill({ status: 422, json: { title: 'Invalid Credential', status: 422, detail: 'basic-auth username is reserved' }, contentType: 'application/problem+json' });
      return route.fulfill({ json: { username: body.username, credential: generated } });
    },
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await openSection(page, 'Basic authentication');
  await page.getByLabel('New credential username').fill('bob');
  await page.getByLabel('New credential password').fill('hunter2');
  await page.getByRole('button', { name: 'Add credential' }).click();
  await expect(page.locator('#credential-message')).toContainText('Added a credential line for bob');
  await expect(page.getByLabel('Credentials', { exact: true })).toHaveValue(`${CREDENTIAL}\n${generated}`);
  await expect(page.getByLabel('New credential password')).toHaveValue('');
  const hash = calls.find(call => call.path === '/v1/util/hash-password');
  expect(JSON.parse(hash.body)).toEqual({ username: 'bob', password: 'hunter2' });
  expect(hash.headers.authorization).toBe('Bearer correct-token');
  // The password never enters the route draft.
  await expect(page.locator('#route-json')).not.toHaveValue(/hunter2/);
  // Client-side rules reject a colon before any request; server rejections are shown inline.
  await page.getByLabel('New credential username').fill('a:b');
  await page.getByLabel('New credential password').fill('x');
  await page.getByRole('button', { name: 'Add credential' }).click();
  await expect(page.locator('#credential-message')).toContainText('cannot contain a colon');
  expect(calls.filter(call => call.path === '/v1/util/hash-password')).toHaveLength(1);
  await page.getByLabel('New credential username').fill('reserved');
  await page.getByLabel('New credential password').fill('x');
  await page.getByRole('button', { name: 'Add credential' }).click();
  await expect(page.locator('#credential-message')).toContainText('reserved');
  await expect(page.getByLabel('Credentials', { exact: true })).toHaveValue(`${CREDENTIAL}\n${generated}`);
});

test('an indeterminate store outcome is surfaced verbatim with a reload action', async ({ page }) => {
  let reloaded = 0;
  await fixtures(page, {
    '/v1/routes/http': route => route.request().method() === 'POST'
      ? route.fulfill({ status: 500, json: { title: 'Indeterminate Outcome', status: 500, detail: 'the shared configuration store did not acknowledge the write; it may have been applied. Reload the current revision before retrying' }, contentType: 'application/problem+json' })
      : (reloaded++, route.fulfill({ json: { revision: 7, routes: config.http }, headers: { etag: '"7"' } })),
  });
  await login(page); await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'New HTTP route' }).click();
  await page.getByLabel('Route id').fill('maybe');
  await page.getByLabel('Backends').fill('http://127.0.0.1:9');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-message')).toContainText('may have been applied');
  const before = reloaded;
  await page.locator('#route-message').getByRole('button', { name: 'Reload routes' }).click();
  await expect.poll(() => reloaded).toBeGreaterThan(before);
});
