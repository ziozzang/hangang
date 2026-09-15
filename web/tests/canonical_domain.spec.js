import { test, expect } from '@playwright/test';
const http={id:'site',hosts:['example.test','www.example.test'],path_prefix:'/',priority:17,backends:['http://127.0.0.1:8080']};
const tcp={id:'unused',listen:'127.0.0.1:9001',backends:['127.0.0.1:9002']};
const source=null;
async function fixture(page, { locale = 'en', initialSource = source } = {}) {
  const routes = { http: new Map([[http.id, structuredClone(http)]]), tcp: new Map([[tcp.id, structuredClone(tcp)]]) };
  const routeWrites = { http: [], tcp: [] }; const configWrites = [];
  let revision = 7;
  let config = { revision, http: [...routes.http.values()], tcp: [...routes.tcp.values()], certificates: [], ...(initialSource ? { geoip_database: structuredClone(initialSource) } : {}) };
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: routes.http.size, tcp_routes: routes.tcp.size, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') { config = request.postDataJSON(); configWrites.push(structuredClone(config)); revision++; config.revision = revision; }
      return handled.fulfill({ json: config, headers: { etag: `"${revision}"` } });
    }
    for (const kind of ['http', 'tcp']) {
      if (path === `/v1/routes/${kind}`) return handled.fulfill({ json: { revision, routes: [...routes[kind].values()] }, headers: { etag: `"${revision}"` } });
      if (path.startsWith(`/v1/routes/${kind}/`)) {
        const id = decodeURIComponent(path.slice(`/v1/routes/${kind}/`.length));
        if (request.method() === 'PUT') { const value = request.postDataJSON(); routeWrites[kind].push(value); routes[kind].set(id, value); revision++; return handled.fulfill({ json: { revision }, headers: { etag: `"${revision}"` } }); }
        return handled.fulfill({ json: routes[kind].get(id), headers: { etag: `"${revision}"` } });
      }
    }
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { routeWrites, configWrites };
}
async function edit(page){await page.locator('[data-view="http"]').click();await page.locator('[data-route-id="site"] td:last-child button').first().click();const d=page.locator('[name="canonical_configured"]').locator('xpath=ancestor::details[1]');if(!(await d.evaluate(n=>n.open)))await d.locator('summary').click();}
async function save(page){await page.locator('#save-route').click();await expect(page.locator('#route-dialog')).toBeHidden();}
test('canonical native form round-trips, validates and removes in EN/KO',async({page})=>{const {routeWrites}=await fixture(page);await edit(page);await page.getByLabel('Configure canonical redirect').check();await page.getByLabel('Canonical redirect active').uncheck();await page.getByLabel('Canonical host').fill('EXAMPLE.TEST');await page.getByLabel('Redirect destination scheme').selectOption('http');await page.getByLabel('Redirect status').selectOption('307');await page.getByLabel('Redirected methods').fill('GET');await page.getByLabel('Included path prefixes').fill('/\n/shop');await page.getByLabel('Excluded path prefixes').fill('/wp-login.php\n/wp-admin/admin-ajax.php\n/wp-admin/admin-post.php');await expect(page.locator('#route-dialog')).toContainText('does not share cookies');await save(page);expect(routeWrites.http[0]).toMatchObject({priority:17,canonical_domain:{enabled:false,host:'example.test',scheme:'http',status:307,path_prefixes:['/','/shop'],exclude_path_prefixes:['/wp-login.php','/wp-admin/admin-ajax.php','/wp-admin/admin-post.php'],methods:['GET']}});await edit(page);await expect(page.getByLabel('Canonical host')).toHaveValue('example.test');await page.getByLabel('Canonical redirect active').check();await save(page);expect(routeWrites.http[1].canonical_domain.enabled).toBe(true);await edit(page);await page.locator('#locale-select-route').selectOption('ko');await expect(page.getByLabel('표준 호스트')).toHaveValue('example.test');await page.getByLabel('표준 호스트').fill('other.example.test');await page.locator('#save-route').click();await expect(page.locator('#route-message')).toContainText('정확한 멤버');await page.getByLabel('표준 호스트').fill('example.test');await page.getByLabel('포함할 경로 접두사').fill('/safe/../admin');await page.locator('#save-route').click();await expect(page.locator('#route-message')).toContainText('절대 경로');await page.getByLabel('포함할 경로 접두사').fill('/');await page.getByLabel('제외할 경로 접두사').fill('/');await page.locator('#save-route').click();await expect(page.locator('#route-message')).toContainText('같을 수 없습니다');await page.getByLabel('제외할 경로 접두사').fill('/wp-login.php');await page.getByLabel('리디렉션할 메서드').fill('GET\nPOST');await page.locator('#save-route').click();await expect(page.locator('#route-message')).toContainText('GET 또는 HEAD');await page.getByLabel('리디렉션할 메서드').fill('GET\nHEAD');await page.locator('[name="require_tls"]').check();await page.locator('#save-route').click();await expect(page.locator('#route-message')).toContainText('TLS 필수');await page.locator('[name="require_tls"]').uncheck();await page.getByLabel('표준 도메인 리디렉션 구성').uncheck();await save(page);expect(routeWrites.http[2]).not.toHaveProperty('canonical_domain');});
