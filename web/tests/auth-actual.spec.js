import { randomBytes } from 'node:crypto';
import { test, expect } from '@playwright/test';

const base = process.env.HANGANG_AUTH_ACTUAL_BASE;
const bootstrapToken = process.env.HANGANG_AUTH_BOOTSTRAP_TOKEN;

test('real backend bootstraps an admin and restricts a newly created viewer', async ({ page, request }) => {
  test.skip(!base || !bootstrapToken, 'Run against an owned fresh instance with HANGANG_AUTH_ACTUAL_BASE and HANGANG_AUTH_BOOTSTRAP_TOKEN.');
  const ownerPassword = `owner-${randomBytes(20).toString('hex')}`;
  const viewerPassword = `viewer-${randomBytes(20).toString('hex')}`;
  const setup = await request.get(`${base}/v1/auth/setup`);
  expect(setup.ok()).toBeTruthy();
  expect((await setup.json()).bootstrap_required).toBe(true);
  const unauthenticatedBootstrap = await request.post(`${base}/v1/auth/bootstrap`, { data: { username: 'owner', password: ownerPassword } });
  expect(unauthenticatedBootstrap.status()).toBe(401);

  await page.goto(`${base}/ui/`);
  await expect(page.getByRole('heading', { name: 'Create the first administrator' })).toBeVisible();
  await page.getByLabel('Bootstrap authorization token').fill(bootstrapToken);
  await page.getByLabel('New administrator username').fill('owner');
  await page.getByLabel('New password', { exact: true }).fill(ownerPassword);
  await page.getByLabel('Confirm password').fill(ownerPassword);
  await page.getByRole('button', { name: 'Create administrator' }).click();
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
  await expect(page.locator('#signed-in-user')).toHaveText('owner · admin');
  const ownerRestore = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/auth/me');
  await page.reload();
  expect((await ownerRestore).status()).toBe(200);
  await expect(page.locator('#signed-in-user')).toHaveText('owner · admin');
  expect((await (await request.get(`${base}/v1/auth/setup`)).json()).bootstrap_required).toBe(false);

  await page.getByRole('link', { name: 'Users' }).click();
  const create = page.locator('#create-user-form');
  await create.locator('[name="username"]').fill('reader');
  await create.locator('[name="password"]').fill(viewerPassword);
  await create.getByRole('button', { name: 'Create user' }).click();
  await expect(page.getByRole('heading', { name: 'reader' })).toBeVisible();
  await page.getByRole('button', { name: 'Log out' }).click();
  await page.locator('#login-username').fill('reader');
  await page.locator('#login-password').fill(viewerPassword);
  const viewerLogin = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/auth/login');
  await page.getByRole('button', { name: 'Sign in' }).click();
  const viewerToken = (await (await viewerLogin).json()).token;
  await expect(page.locator('#signed-in-user')).toHaveText('reader · viewer');
  const viewerRestore = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/auth/me');
  await page.reload();
  expect((await viewerRestore).status()).toBe(200);
  await expect(page.locator('#signed-in-user')).toHaveText('reader · viewer');
  await expect(page.getByRole('link', { name: 'Users' })).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Proxy status' })).toBeVisible();
  expect((await request.get(`${base}/v1/config`, { headers: { Authorization: `Bearer ${viewerToken}` } })).status()).toBe(403);
  expect((await request.get(`${base}/v1/users`, { headers: { Authorization: `Bearer ${viewerToken}` } })).status()).toBe(403);
});
