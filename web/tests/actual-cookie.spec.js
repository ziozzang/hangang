import { test, expect, chromium } from '@playwright/test';

const base = process.env.HANGANG_COOKIE_ACTUAL_BASE;
const expectation = process.env.HANGANG_COOKIE_EXPECT || 'pass';
test.use({ ignoreHTTPSErrors: true });

test('Chromium login cookies survive HTTP/2 to HTTP/1 translation', async ({ page }) => {
  test.skip(!base, 'Requires the owned cookie browser fixture.');
  const exercise = async current => {
    const seed = await current.goto(`${base}/seed`);
    expect(seed.status()).toBe(200);
    expect((await seed.headersArray()).filter(header => header.name.toLowerCase() === 'set-cookie')).toHaveLength(2);
    const result = await current.evaluate(async () => {
      const response = await fetch('/login', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'log=owned-user&pwd=synthetic-password&redirect_to=%2Faccount',
      });
      return { status: response.status, body: await response.json() };
    });
    const account = await current.evaluate(async () => {
      const response = await fetch('/account');
      return { status: response.status, body: await response.json() };
    });
    const protocol = await current.evaluate(() => performance.getEntriesByType('resource')
      .filter(entry => entry.name.endsWith('/login')).at(-1)?.nextHopProtocol ?? '');
    return { result, account, protocol };
  };

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/login', requestStage: 'Request' },
    { urlPattern: '*/account', requestStage: 'Request' }] });
  cdp.on('Fetch.requestPaused', event => {
    const cookie = Object.entries(event.request.headers).find(([name]) => name.toLowerCase() === 'cookie')?.[1] ?? '';
    const crumbs = cookie.split(/;\s*/).filter(Boolean);
    const headers = Object.entries(event.request.headers)
      .filter(([name]) => name.toLowerCase() !== 'cookie')
      .map(([name, value]) => ({ name, value }));
    headers.push(...crumbs.map(value => ({ name: 'Cookie', value })));
    cdp.send('Fetch.continueRequest', { requestId: event.requestId, headers }).catch(() => {});
  });
  const h2 = await exercise(page);
  const stored = await page.context().cookies(base);
  expect(stored.map(cookie => cookie.name)).toEqual(expect.arrayContaining([
    'wordpress_test_cookie', 'wordpress_logged_in', 'wordpress_sec', 'wordpress_pref',
  ]));
  expect(h2.protocol).toBe('h2');
  expect(h2.result.body.method).toBe('POST');
  expect(h2.result.body.body).toBe('log=owned-user&pwd=synthetic-password&redirect_to=%2Faccount');
  expect(h2.result.body.set_cookie_count).toBe(2);
  const h2Complete = h2.result.status === 200 && h2.result.body.cookie_names.includes('wordpress_test_cookie')
    && h2.result.body.cookie_names.includes('wordpress_logged_in') && h2.account.status === 200
    && h2.account.body.cookie_names.includes('wordpress_sec')
    && h2.account.body.cookie_names.includes('wordpress_pref');

  const h1Browser = await chromium.launch({ headless: true, args: ['--disable-http2'] });
  try {
    const h1Page = await h1Browser.newPage({ ignoreHTTPSErrors: true });
    const h1 = await exercise(h1Page);
    expect(h1.protocol).toBe('http/1.1');
    expect(h1.result.status).toBe(200);
    expect(h1.result.body.cookie_names).toEqual(expect.arrayContaining(['wordpress_test_cookie', 'wordpress_logged_in']));
    expect(h1.account.status).toBe(200);
    expect(h1.account.body.cookie_names).toEqual(expect.arrayContaining(['wordpress_sec', 'wordpress_pref']));
  } finally {
    await h1Browser.close();
  }

  if (expectation === 'fail') expect(h2Complete, 'old binary unexpectedly preserved all HTTP/2 cookie crumbs').toBe(false);
  else expect(h2Complete, JSON.stringify(h2)).toBe(true);
});
