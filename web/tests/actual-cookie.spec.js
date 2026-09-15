import { test, expect, chromium } from '@playwright/test';

const base = process.env.HANGANG_COOKIE_ACTUAL_BASE;
test.use({ ignoreHTTPSErrors: true });

test('Chromium login cookies survive HTTP/2 to HTTP/1 translation', async ({ page }) => {
  test.skip(!base, 'Requires the owned cookie browser fixture.');
  const exercise = async current => {
    const seed = await current.goto(`${base}/seed`);
    expect(seed.status()).toBe(200);
    expect((await seed.headersArray()).filter(header => header.name.toLowerCase() === 'set-cookie')).toHaveLength(4);
    const [loginResponse, result] = await Promise.all([
      current.waitForResponse(response => response.url().endsWith('/login')),
      current.evaluate(async () => {
      const response = await fetch('/login', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'log=owned-user&pwd=synthetic-password&redirect_to=%2Faccount',
      });
      return { status: response.status, body: await response.json() };
    }),
    ]);
    const loginSetCookieCount = (await loginResponse.headersArray())
      .filter(header => header.name.toLowerCase() === 'set-cookie').length;
    const account = await current.evaluate(async () => {
      try {
        const response = await fetch('/account');
        return { status: response.status, body: await response.json() };
      } catch (error) { return { status: 0, body: { error: error.name } }; }
    });
    const protocol = await current.evaluate(() => performance.getEntriesByType('resource')
      .filter(entry => entry.name.endsWith('/login')).at(-1)?.nextHopProtocol ?? '');
    return { result, account, protocol, loginSetCookieCount };
  };

  const h2 = await exercise(page);
  const stored = await page.context().cookies(base);
  expect(stored.map(cookie => cookie.name)).toEqual(expect.arrayContaining([
    'wordpress_test_cookie', 'wordpress_logged_in', 'wordpress_sec', 'wordpress_pref',
  ]));
  expect(h2.protocol).toBe('h2');
  expect(h2.result.body.method).toBe('POST');
  expect(h2.result.body.body).toBe('log=owned-user&pwd=synthetic-password&redirect_to=%2Faccount');
  expect(h2.result.body.cookie_field_count).toBe(1);
  expect(h2.loginSetCookieCount).toBe(2);
  const h2Complete = h2.result.status === 200 && h2.result.body.cookie_names.includes('wordpress_test_cookie')
    && h2.result.body.cookie_names.includes('wordpress_logged_in')
    && h2.result.body.cookie_names.includes('wordpress_sec_seed')
    && h2.result.body.cookie_names.includes('wordpress_settings') && h2.account.status === 200
    && h2.account.body.cookie_names.includes('wordpress_sec')
    && h2.account.body.cookie_names.includes('wordpress_pref')
    && h2.account.body.cookie_field_count === 1;

  const h1Browser = await chromium.launch({ headless: true, args: ['--disable-http2'] });
  try {
    const h1Page = await h1Browser.newPage({ ignoreHTTPSErrors: true });
    const h1 = await exercise(h1Page);
    expect(h1.protocol).toBe('http/1.1');
    expect(h1.result.status).toBe(200);
    expect(h1.result.body.cookie_names).toEqual(expect.arrayContaining(['wordpress_test_cookie', 'wordpress_logged_in', 'wordpress_sec_seed', 'wordpress_settings']));
    expect(h1.account.status).toBe(200);
    expect(h1.account.body.cookie_names).toEqual(expect.arrayContaining(['wordpress_sec', 'wordpress_pref']));
  } finally {
    await h1Browser.close();
  }

  expect(h2Complete, JSON.stringify(h2)).toBe(true);
});
