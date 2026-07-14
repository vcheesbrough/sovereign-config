const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const configScript = 'globalThis.SOVEREIGN_CONFIG={issuer:"https://auth.example.test/application/o/browser/",clientId:"browser"};';

function grpcFrame(payload) {
  const dataHeader = Buffer.alloc(5);
  dataHeader.writeUInt32BE(payload.length, 1);
  const trailer = Buffer.from('grpc-status: 0\r\n');
  const trailerHeader = Buffer.alloc(5);
  trailerHeader[0] = 0x80;
  trailerHeader.writeUInt32BE(trailer.length, 1);
  return Buffer.concat([dataHeader, payload, trailerHeader, trailer]);
}

async function mockApplication(page) {
  await page.route('**/app-config.js', route => route.fulfill({
    contentType: 'text/javascript',
    body: configScript
  }));
  await page.route('**/sovereign.config.v1.System/GetVersion', route => {
    const application = Buffer.from('1.3.0');
    const protocol = Buffer.from('v1');
    const message = Buffer.concat([
      Buffer.from([0x0a, application.length]), application,
      Buffer.from([0x12, protocol.length]), protocol
    ]);
    return route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(message)
    });
  });
}

test.beforeEach(async ({ page }) => {
  await mockApplication(page);
});

test('reports service and logged-out state accessibly', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByText('Available')).toBeVisible();
  await expect(page.getByText('1.3.0')).toBeVisible();
  await expect(page.getByText('Logged out')).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  await page.screenshot({
    path: `screenshots/status-${testInfo.project.name}.png`,
    animations: 'disabled'
  });
});

test('keyboard login creates an S256 request without exposing a verifier', async ({ page }) => {
  await page.route('**/.well-known/openid-configuration', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      authorization_endpoint: 'https://auth.example.test/application/o/authorize/',
      token_endpoint: 'https://auth.example.test/application/o/token/'
    })
  }));
  const authorization = page.waitForRequest('https://auth.example.test/application/o/authorize/**');
  await page.route('https://auth.example.test/application/o/authorize/**', route => route.fulfill({
    contentType: 'text/html',
    body: '<h1>Identity provider</h1>'
  }));

  await page.goto('/');
  const login = page.getByRole('button', { name: 'Log in' });
  await login.focus();
  await expect(login).toBeFocused();
  await page.keyboard.press('Enter');
  const request = await authorization;
  const url = new URL(request.url());
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('code_challenge')).toBeTruthy();
  expect(url.searchParams.get('state')).toBeTruthy();
  expect(url.searchParams.has('code_verifier')).toBe(false);
});

test('reload starts logged out without recovering an access token', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Logged out')).toBeVisible();
  await page.reload();
  await expect(page.getByText('Logged out')).toBeVisible();
});
