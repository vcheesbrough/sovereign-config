const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { signedOut, signedIn, tokenEndpoint, openCallback, mockApplication, mockDiscovery } = require('./helpers');

// Card #565: without a session, every view but Downloads is a sign-in card that
// says what is being logged in to. The brand menu lists every view; picking
// one that needs a session opens the card.

const REPOSITORY = 'https://github.com/vcheesbrough/sovereign-config';
const AMBER = 'rgb(251, 191, 36)';

function card(page) {
  return page.locator('#sign-in-page');
}

async function openMenu(page) {
  await page.getByRole('button', { name: 'Sovereign Config' }).click();
  return page.getByRole('navigation', { name: 'Views' });
}

test.describe('sign-in', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('a signed-out visit is a card naming the server and the identity provider', async ({ page }, testInfo) => {
    const rpcs = [];
    page.on('request', request => {
      if (request.url().includes('/sovereign.config.')) rpcs.push(new URL(request.url()).pathname);
    });
    await page.goto('/');

    await expect(card(page)).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Sovereign Config', level: 1 })).toBeVisible();
    const tagline = card(page).locator('.tagline');
    await expect(tagline).toHaveText("Your keys. Your box. Nobody else's business.");
    // Three beats, one to a line, the last in the heading amber.
    const lines = tagline.locator('span');
    await expect(lines).toHaveCount(3);
    const tops = await lines.evaluateAll(spans => spans.map(span => span.getBoundingClientRect().top));
    expect(tops[0]).toBeLessThan(tops[1]);
    expect(tops[1]).toBeLessThan(tops[2]);
    await expect(lines.nth(2)).toHaveCSS('color', AMBER);

    await expect(page.locator('#sign-in-host')).toHaveText('127.0.0.1:8088');
    await expect(page.locator('#sign-in-version')).toHaveText('1.5.0');
    await expect(page.locator('#sign-in-issuer')).toHaveText('auth.example.test');

    // The card's Log in is the one on offer; nothing reports an error, the
    // empty editor and the tree are gone, and nothing protected was asked for.
    await expect(signedOut(page)).toHaveCount(1);
    await expect(page.locator('#error')).toBeHidden();
    await expect(page.locator('#configuration-page')).toBeHidden();
    await expect(page.locator('#sidebar')).toBeHidden();
    expect(rpcs.filter(rpc => !/Handshake|GetVersion/.test(rpc))).toEqual([]);

    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/sign-in-${testInfo.project.name}.png`,
      animations: 'disabled'
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(card(page)).toBeVisible();
    await page.screenshot({
      path: `screenshots/sign-in-narrow-${testInfo.project.name}.png`,
      animations: 'disabled'
    });
  });

  for (const deepLink of ['/configuration/apps/api', '/connections/', '/audit/']) {
    test(`a signed-out deep link to ${deepLink} shows the card and keeps its URL`, async ({ page }) => {
      await page.goto(deepLink);
      await expect(card(page)).toBeVisible();
      await expect(page.locator('#error')).toBeHidden();
      expect(new URL(page.url()).pathname.replace(/\/$/, '')).toBe(deepLink.replace(/\/$/, ''));
    });
  }

  test('the menu lists every view, and picking one that needs a session opens the card', async ({ page }, testInfo) => {
    // From Downloads, the one view that needs no session (the test server
    // serves only `/`, so it is reached by its link).
    await page.goto('/');
    await page.getByRole('link', { name: 'Get the CLI and MCP server' }).click();
    await expect(page.getByRole('heading', { name: 'Downloads', level: 1 })).toBeVisible();
    let menu = await openMenu(page);
    for (const name of ['Configuration values', 'Access URLs', 'Audit trail']) {
      const link = menu.getByRole('link', { name, exact: true });
      await expect(link).toHaveAttribute('data-needs-login', '');
      await expect(link).toHaveAttribute('title', 'Log in to open');
      await expect(link).not.toHaveAttribute('aria-disabled');
    }
    await expect(menu.getByRole('link', { name: 'Downloads', exact: true })).not.toHaveAttribute('data-needs-login');

    expect((await new AxeBuilder({ page }).include('#brand-menu').analyze()).violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/sign-in-menu-${testInfo.project.name}.png`,
      animations: 'disabled'
    });

    await page.keyboard.press('Escape');
    await expect(page.getByRole('navigation', { name: 'Views' })).toBeHidden();
    for (const [name, url] of [['Audit trail', /\/audit\/$/], ['Access URLs', /\/connections\/$/], ['Configuration values', /\/configuration\/$/]]) {
      menu = await openMenu(page);
      await menu.getByRole('link', { name, exact: true }).click();
      await expect(page).toHaveURL(url);
      await expect(card(page)).toBeVisible();
      await expect(page.locator('#error')).toBeHidden();
    }
  });

  test('keyboard reaches every menu entry', async ({ page }) => {
    await page.goto('/');
    await openMenu(page);
    for (const name of ['Configuration values', 'Access URLs', 'Audit trail', 'Downloads']) {
      await page.keyboard.press('Tab');
      await expect(page.getByRole('link', { name, exact: true })).toBeFocused();
    }
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: /Project on GitHub/ })).toBeFocused();
  });

  test('Downloads is open without a session, with the header Log in', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Get the CLI and MCP server' }).click();
    await expect(page).toHaveURL(/\/downloads$/);
    await expect(page.getByRole('heading', { name: 'Downloads', level: 1 })).toBeVisible();
    await expect(card(page)).toBeHidden();
    await expect(page.locator('#login')).toBeVisible();
  });

  test("the card's Log in remembers the deep link it was opened on", async ({ page }) => {
    await mockDiscovery(page);
    // The redirect leaves this origin, taking its session storage with it, so
    // the write is recorded as it happens.
    const stored = {};
    await page.exposeBinding('recordStorage', (_source, key, value) => { stored[key] = value; });
    await page.addInitScript(() => {
      const setItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function (key, value) {
        window.recordStorage(key, value);
        return setItem.call(this, key, value);
      };
    });
    const authorization = page.waitForRequest('https://auth.example.test/application/o/authorize/**');
    await page.route('https://auth.example.test/application/o/authorize/**', route => route.fulfill({
      contentType: 'text/html',
      body: '<h1>Identity provider</h1>'
    }));
    await page.goto('/connections/');
    await card(page).getByRole('button', { name: 'Log in' }).click();
    await authorization;
    expect(stored['sovereign-config.return-path']).toBe('/connections/');
  });

  for (const session of ['signed out', 'signed in']) {
    test(`the menu links to the project on GitHub when ${session}`, async ({ page }) => {
      if (session === 'signed in') {
        await openCallback(page);
      } else {
        await page.goto('/');
      }
      const menu = await openMenu(page);
      const github = menu.getByRole('link', { name: /Project on GitHub/ });
      await expect(github).toHaveAttribute('href', REPOSITORY);
      await expect(github).toHaveAttribute('target', '_blank');
      await expect(github).toHaveAttribute('rel', 'noopener noreferrer');
      await expect(github).toHaveAccessibleName('Project on GitHub (opens in a new tab)');
      if (session === 'signed in') {
        await expect(menu.getByRole('link', { name: 'Audit trail', exact: true })).not.toHaveAttribute('data-needs-login');
      }
    });
  }

  test('a session that ends while the page loads turns the view into the card', async ({ page }) => {
    // The stored session is past its absolute expiry, which the status check
    // discovers only after the first render.
    await openCallback(page, 'success', 'expected-state', 0, true);
    await expect(card(page)).toBeVisible();
    await expect(page.getByText('authentication required')).toBeVisible();
    await expect(page.locator('#configuration-page')).toBeHidden();
  });

  test('a failed login callback still ends on the card', async ({ page }) => {
    await openCallback(page, 'success', 'wrong-state');
    await expect(page.getByText('login response did not match this browser')).toBeVisible();
    await expect(card(page)).toBeVisible();
  });

  test('a refresh in flight is not mistaken for being signed out', async ({ page }) => {
    const refresh = page.waitForRequest(request => request.url() === tokenEndpoint
      && (request.postData() || '').includes('grant_type=refresh_token'));
    // Long enough that every assertion below lands while the identity
    // provider is still answering: once it does, the page re-renders, which
    // would hide the card whatever the fix.
    test.setTimeout(30000);
    await openCallback(page, 'success', 'expected-state', 0, false, undefined, 8000);
    await refresh;
    const during = { timeout: 1500 };
    const menu = await openMenu(page);
    const accessUrls = menu.getByRole('link', { name: 'Access URLs', exact: true });
    await expect(accessUrls).not.toHaveAttribute('data-needs-login', during);
    await accessUrls.click();
    await expect(page).toHaveURL(/\/connections\/$/, during);
    await expect(card(page)).toBeHidden(during);
    await expect(page.locator('#connections-page')).toBeVisible(during);
  });

  test('logging out returns a protected view to the card, focused on its Log in', async ({ page }) => {
    await openCallback(page);
    await expect(card(page)).toBeHidden();
    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(card(page)).toBeVisible();
    await expect(card(page).getByRole('button', { name: 'Log in' })).toBeFocused();
  });
});
