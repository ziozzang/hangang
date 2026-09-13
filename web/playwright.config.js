import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 20_000,
  use: {
    baseURL: 'http://127.0.0.1:41739',
    headless: true,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node tests/fixture-server.js',
    url: 'http://127.0.0.1:41739/ui/',
    reuseExistingServer: false,
  },
});
