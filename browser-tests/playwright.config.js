const { defineConfig, devices } = require('@playwright/test');

// With PLAYWRIGHT_STATIC set, serve a prebuilt release bundle; otherwise
// `trunk serve` builds into target/trunk-dist (Trunk.toml), never web-dist/.
// tests/helpers.js reads index.html from the same place.
const staticDir = process.env.PLAYWRIGHT_STATIC_DIR || '../web-dist';

module.exports = defineConfig({
  testDir: './tests',
  outputDir: './test-results',
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:8088',
    viewport: { width: 1280, height: 800 },
    reducedMotion: 'reduce',
    trace: 'retain-on-failure'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } }
  ],
  webServer: {
    command: process.env.PLAYWRIGHT_STATIC
      ? `npx http-server ${JSON.stringify(staticDir)} -a 127.0.0.1 -p 8088 -c-1`
      : 'NO_COLOR=false trunk serve --address 127.0.0.1 --port 8088',
    cwd: process.env.PLAYWRIGHT_STATIC ? '.' : '../crates/sovereign-config-web',
    url: 'http://127.0.0.1:8088',
    reuseExistingServer: true,
    timeout: 120000
  }
});
