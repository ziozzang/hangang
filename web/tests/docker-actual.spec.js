import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_DOCKER_ACTUAL_BASE;
const token = process.env.HANGANG_DOCKER_ACTUAL_TOKEN;
const candidateSocket = process.env.HANGANG_DOCKER_ACTUAL_SOCKET;
const defaultSocket = process.env.HANGANG_DOCKER_ACTUAL_DEFAULT_SOCKET || `${candidateSocket}.default`;

test('real Docker UI tests, saves, disables and restores an owned Unix connection', async ({ page, request }) => {
  test.skip(!base || !token || !candidateSocket, 'Run tests/docker_web_smoke.py against its owned Unix Docker fixtures.');
  const authorization = { Authorization: `Bearer ${token}` };
  const connection = async () => {
    const response = await request.get(`${base}/v1/docker/connection`, { headers: authorization });
    expect(response.status()).toBe(200);
    return response.json();
  };
  const resolve = async () => {
    const response = await request.post(`${base}/v1/docker/resolve`, {
      headers: authorization,
      data: { container: 'api', network: 'edge', port: 8080 },
    });
    return response;
  };

  await page.goto(`${base}/ui/`);
  await page.getByRole('button', { name: 'Use administrator token' }).click();
  await page.getByLabel('Administrator token').fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="docker"]').click();
  await expect(page.locator('#docker-connection-source')).toContainText('revision 0');
  expect(await connection()).toMatchObject({
    revision: 0, source: 'cli', enabled: true,
    config: { transport: 'unix', socket_path: defaultSocket },
  });

  await page.locator('#docker-connection-socket_path').fill(candidateSocket);
  await page.locator('#docker-connection-test').click();
  await expect(page.locator('#docker-connection-message')).toContainText('has not been saved');
  expect(await connection()).toMatchObject({
    revision: 0, source: 'cli', config: { socket_path: defaultSocket },
  });
  for (const [name, value] of Object.entries({ container: 'api', network: 'edge', port: '8080' })) {
    await page.locator(`#docker-inspect-${name}`).fill(value);
  }
  await page.locator('#docker-inspect-submit').click();
  await expect(page.locator('#docker-inspect-result')).toContainText('http://192.0.2.42:8080');

  await page.locator('#docker-connection-save').click();
  await expect(page.locator('#docker-connection-source')).toContainText('revision 1');
  expect(await connection()).toMatchObject({
    revision: 1, source: 'managed', enabled: true,
    config: { transport: 'unix', socket_path: candidateSocket },
  });
  await page.locator('#docker-inspect-submit').click();
  await expect(page.locator('#docker-inspect-result')).toContainText('http://192.0.2.41:8080');
  expect(await (await resolve()).json()).toEqual({
    http_backend: 'http://192.0.2.41:8080', tcp_backend: '192.0.2.41:8080',
  });

  await page.locator('#docker-connection-transport').selectOption('disabled');
  await page.locator('#docker-connection-save').click();
  await expect(page.locator('#docker-connection-state')).toHaveText('Docker connection disabled');
  expect(await connection()).toMatchObject({
    revision: 2, source: 'disabled', enabled: false, config: { transport: 'disabled' },
  });
  expect((await resolve()).status()).toBe(404);

  await page.locator('#docker-connection-reset').click();
  await expect(page.locator('#docker-connection-source')).toContainText('revision 3');
  expect(await connection()).toMatchObject({
    revision: 3, source: 'cli', enabled: true,
    config: { transport: 'unix', socket_path: defaultSocket },
  });
  await page.locator('#docker-inspect-submit').click();
  await expect(page.locator('#docker-inspect-result')).toContainText('http://192.0.2.42:8080');

  const browserSecrets = await page.evaluate(() => ({
    local: Object.values(localStorage), session: Object.values(sessionStorage), cookie: document.cookie,
  }));
  expect([...browserSecrets.local, ...browserSecrets.session, browserSecrets.cookie].join('\n')).not.toContain(token);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.locator('#docker-connection-socket_path')).toHaveValue('');
});
