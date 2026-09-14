import { defineConfig } from '@playwright/test';

const port = Number(process.env.HANGANG_UI_TEST_PORT || 41739);

export default defineConfig({
  testDir: './tests',
  timeout: 20_000,
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node tests/fixture-server.js',
    url: `http://127.0.0.1:${port}/ui/`,
    reuseExistingServer: false,
  },
});
