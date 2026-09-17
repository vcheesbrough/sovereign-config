const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const transportContract = require('../../test-contracts/transport.json');
const {
  tokenEndpoint,
  signedIn,
  signedOut,
  openView,
  storedRefreshState,
  mockValues,
  mockApplication,
  mockDiscovery,
  openCallback
} = require('./helpers');

test.describe('auth', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('reports service and logged-out state accessibly', async ({ page }, testInfo) => {
    await page.goto('/');
    // A reachable service says so by reporting its version, not by wearing a
    // badge; the badge is reserved for the failure the operator must act on.
    await expect(page.locator('#version-value')).toHaveText('1.5.0');
    // The protocol version is a client-compatibility concern, not an operator's:
    // the service still reports it, and the header deliberately does not.
    await expect(page.locator('header').getByText(/protocol/i)).toHaveCount(0);
    await expect(page.locator('#service-value')).toBeHidden();
    await expect(signedOut(page)).toBeVisible();
    // `/` is the configuration root now that the System view is gone.
    await expect(page).toHaveURL(/\/configuration\/$/);
    await expect(page.getByRole('heading', { name: 'Configuration values' })).toBeVisible();

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/status-${testInfo.project.name}.png`,
      animations: 'disabled'
    });
  });

  test('keyboard login creates an S256 offline request without exposing a verifier', async ({ page }) => {
    await mockDiscovery(page);
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
    // `profile` and `email` are requested so the ID token carries a claim a
    // person recognises; without them the provider releases only its hashed
    // `sub`. `email` is a separate scope from `profile`, so both are needed for
    // the header's full name → preferred_username → email fallback to work.
    expect(url.searchParams.get('scope'))
      .toBe('openid profile email sovereign-config offline_access');
    expect(url.searchParams.has('code_verifier')).toBe(false);
  });

  test('callback refreshes an expired access token and rotates the refresh token', async ({ page }) => {
    const requests = await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    expect(requests).toHaveLength(2);
    expect(requests[0]).toMatchObject({
      grant_type: 'authorization_code',
      code: 'test-code',
      code_verifier: 'test-verifier'
    });
    expect(requests[1]).toMatchObject({
      grant_type: 'refresh_token',
      refresh_token: 'refresh-token-one'
    });
  });

  test('same-page navigation does not discard the in-memory login session', async ({ page }) => {
    await openCallback(page);
    await mockValues(page);
    await expect(signedIn(page)).toBeVisible();
    await openView(page, 'Configuration values');
    await expect(page).toHaveURL(/\/configuration\/$/);
    await expect(page.getByRole('heading', { name: 'Configuration values' })).toBeVisible();
    await openView(page, 'Downloads');
    await expect(page).toHaveURL(/\/downloads$/);
    await expect(signedIn(page)).toBeVisible();
  });

  test('refresh rejection clears the browser session', async ({ page }) => {
    await openCallback(page, 'rejected');
    await expect(signedOut(page)).toBeVisible();
    await expect(page.getByText('login has expired')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
    await expect.poll(() => storedRefreshState(page))
      .toEqual({ token: null, endpoint: null, expiry: null });
  });

  test('refresh outage does not reuse an expired access token', async ({ page }) => {
    await openCallback(page, 'unavailable');
    await expect(page.getByText('service is unavailable')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();
  });

  test('transient refresh HTTP failure preserves the browser session', async ({ page }) => {
    await openCallback(page, 'transient');
    await expect(page.getByText('identity provider is unavailable')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();
    await expect.poll(() => storedRefreshState(page)).toMatchObject({
      token: 'refresh-token-one',
      endpoint: tokenEndpoint
    });
  });

  test('absolute refresh expiry clears the browser session without a token request', async ({ page }) => {
    const requests = await openCallback(page, 'success', 'expected-state', 0, true);
    await expect(signedOut(page)).toBeVisible();
    await expect(page.getByText('authentication required')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
    await expect.poll(() => storedRefreshState(page))
      .toEqual({ token: null, endpoint: null, expiry: null });
    expect(requests).toHaveLength(1);
    expect(requests[0].grant_type).toBe('authorization_code');
  });

  test('keyboard logout clears the in-memory session and restores focus', async ({ page }) => {
    await openCallback(page);
    const logout = page.getByRole('button', { name: 'Log out' });
    await expect(logout).toBeVisible();
    await logout.focus();
    await page.keyboard.press('Enter');
    await expect(signedOut(page)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log in' })).toBeFocused();
  });

  test('callback rejects a mismatched state without exchanging the code', async ({ page }) => {
    const requests = await openCallback(page, 'success', 'wrong-state');
    await expect(signedOut(page)).toBeVisible();
    await expect(page.getByText('login response did not match this browser')).toBeVisible();
    expect(requests).toHaveLength(0);
  });

  test('the header names the signed-in operator and forgets them on logout', async ({ page }) => {
    await openCallback(page);
    const identity = page.locator('#identity-name');
    await expect(identity).toHaveText('A Vincent');
    // The name outlives a reload: the refresh token is restored from session
    // storage, and so is the label that goes with it.
    await page.reload();
    await expect(identity).toHaveText('A Vincent');

    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(signedOut(page)).toBeVisible();
    await expect(identity).toBeHidden();
    expect(await page.evaluate(() => sessionStorage.getItem('sovereign-config.identity-name')))
      .toBeNull();
  });

  test('the header falls back through the ID token claims it is given', async ({ page }) => {
    await openCallback(page, 'success', 'expected-state', 0, false, {
      sub: 'operator-subject',
      email: 'operator@example.test'
    });
    await expect(page.locator('#identity-name')).toHaveText('operator@example.test');
  });

  test('the header stays unlabelled rather than showing an opaque subject', async ({ page }) => {
    // `sub` is hashed by the provider, so it names nobody. An unlabelled header
    // says more about the session than 64 characters of hex would.
    await openCallback(page, 'success', 'expected-state', 0, false, { sub: 'operator-subject' });
    await expect(signedIn(page)).toBeVisible();
    await expect(page.locator('#identity-name')).toBeHidden();
  });

  test('a session without an ID token is labelled by its buttons alone', async ({ page }) => {
    await openCallback(page, 'success', 'expected-state', 0, false, null);
    await expect(signedIn(page)).toBeVisible();
    await expect(page.locator('#identity-name')).toBeHidden();
  });

  test('reload restores the session with a rotated refresh token', async ({ page }) => {
    const requests = await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.reload();
    await expect(signedIn(page)).toBeVisible();
    expect(requests).toHaveLength(3);
    expect(requests[2]).toMatchObject({
      grant_type: 'refresh_token',
      refresh_token: 'refresh-token-two'
    });
  });

  for (const contract of transportContract) {
    test(`browser transport maps gRPC status ${contract.grpc_status}`, async ({ page }) => {
      const requests = await openCallback(page, 'success', 'expected-state', contract.grpc_status);
      if (contract.grpc_status === 0) {
        await expect(signedIn(page)).toBeVisible();
        return;
      }
      await expect(page.getByText(contract.message, { exact: true })).toBeVisible();
      // Only an Unauthenticated answer ends the session; every other failure is
      // the service's, so Log out stays on offer.
      const session = contract.grpc_status === 16 ? signedOut(page) : signedIn(page);
      await expect(session).toBeVisible();
      if (contract.grpc_status === 16) {
        await expect.poll(() => storedRefreshState(page))
          .toEqual({ token: null, endpoint: null, expiry: null });
        await page.reload();
        await expect(signedOut(page)).toBeVisible();
        expect(requests).toHaveLength(2);
      }
    });
  }
});
