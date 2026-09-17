const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  mockValues,
  mockApplication,
  mockConnections,
  openCallback,
  openConfiguration
} = require('./helpers');

test.describe('navigation', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('configuration path is deep-linked, selectable, and restored by browser history', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {
      '/apps/api/feature-flag': 'enabled',
      '/apps/worker/concurrency': '4'
    });
    await page.goto('/configuration/apps/api');
    const pathInput = page.getByLabel('Selected path');
    await expect(pathInput).toHaveValue('/apps/api');
    await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();
    await expect(page.locator('#existing-paths [role="option"]')).toHaveCount(4);

    // The field and the URL both echo back exactly what was typed — case is
    // retained, not folded — even though the request underneath resolves the
    // path case-insensitively (card #294).
    await pathInput.fill('/Apps/Worker');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(page).toHaveURL(/\/configuration\/Apps\/Worker$/);
    await expect(pathInput).toHaveValue('/Apps/Worker');
    await expect(page.getByRole('row', { name: /concurrency/ })).toBeVisible();

    await page.goBack();
    await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
    await expect(pathInput).toHaveValue('/apps/api');
    await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();
  });

  test('path selector refreshes external paths and Enter opens the selected path', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/apps/api/feature-flag': 'enabled'
    });
    await page.goto('/configuration/apps/api');
    const pathInput = page.getByLabel('Selected path');
    await expect(page.locator('#existing-paths [role="option"][data-path="/services/worker"]')).toHaveCount(0);

    values.setValue('/services/worker/concurrency', '4');
    await pathInput.focus();
    const workerPath = page.locator('#existing-paths [role="option"][data-path="/services/worker"]');
    await expect(workerPath).toHaveCount(1);

    await workerPath.click();
    await expect(pathInput).toHaveValue('/services/worker');
    await pathInput.press('Enter');
    await expect(page).toHaveURL(/\/configuration\/services\/worker$/);
    await expect(page.getByRole('row', { name: /concurrency/ })).toBeVisible();
  });

  test('path selector autocomplete finds and does not duplicate a mixed-case namespace', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {
      '/Apps/API/serverIP': '10.0.0.1'
    });
    // The URL segment is always lowercase; the value's namespace was
    // established as "/Apps/API". Before this fix the selector listed both
    // spellings as separate rows, and typing the lowercase query found
    // neither (card #294 follow-up).
    await page.goto('/configuration/apps/api');
    const pathInput = page.getByLabel('Selected path');
    await pathInput.focus();
    const option = page.locator('#existing-paths [role="option"][data-path="/Apps/API"]');
    await expect(option).toHaveCount(1);

    await pathInput.fill('/a');
    await expect(option).toBeVisible();
    await expect(option).toHaveText('/Apps/API');
  });

  test('path selector popup uses the available viewport height', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const initial = Object.fromEntries(
      Array.from({ length: 40 }, (_, index) => [`/services/service-${index + 1}/enabled`, 'true'])
    );
    await mockValues(page, initial);
    await page.goto('/configuration/services/service-1');
    const pathInput = page.getByLabel('Selected path');
    await pathInput.focus();
    const popup = page.getByRole('listbox', { name: 'Existing paths' });
    await expect(popup).toBeVisible();
    await expect(page.locator('#existing-paths [role="option"]')).toHaveCount(42);

    const bounds = await popup.boundingBox();
    expect(bounds.height).toBeGreaterThan(400);
    expect(bounds.y + bounds.height).toBeLessThanOrEqual(page.viewportSize().height - 8);

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);

    await page.setViewportSize({ width: 390, height: 420 });
    const mobileBounds = await popup.boundingBox();
    expect(mobileBounds.y).toBeGreaterThanOrEqual(8);
    expect(mobileBounds.y + mobileBounds.height).toBeLessThanOrEqual(page.viewportSize().height - 8);
  });

  test('configuration grid is accessible and contained on desktop and mobile', async ({ page }, testInfo) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {
      '/apps/api/feature-flag': 'enabled',
      '/apps/api/retry-limit': '5'
    });
    await page.goto('/configuration/apps/api');
    await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/configuration-${testInfo.project.name}.png`,
      animations: 'disabled'
    });

    await page.setViewportSize({ width: 390, height: 844 });
    const containment = await page.evaluate(() => {
      const grid = document.querySelector('.table-scroll');
      window.scrollTo({ left: 100, top: 0 });
      return {
        bodyContained: document.body.scrollWidth <= innerWidth,
        documentScroll: scrollX,
        gridScrollable: grid.scrollWidth > grid.clientWidth
      };
    });
    expect(containment).toEqual({ bodyContained: true, documentScroll: 0, gridScrollable: false });
    await page.evaluate(() => new Promise(resolve => {
      requestAnimationFrame(() => requestAnimationFrame(resolve));
    }));
    await page.screenshot({
      path: `screenshots/configuration-mobile-${testInfo.project.name}.png`,
      animations: 'disabled'
    });
  });

  test('a browser Back closes an open brand menu', async ({ page }) => {
    await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {});
    await openConfiguration(page);
    await openView(page, 'Access URLs');
    await expect(page).toHaveURL(/\/connections\/$/);

    // Left open rather than dismissed by the navigation that got here — the
    // in-app link path already closes the menu, so a Back press is the only way
    // to reach this state.
    const menuButton = page.getByRole('button', { name: 'Sovereign Config' });
    await menuButton.click();
    await expect(page.locator('#brand-menu')).toBeVisible();

    // Regression: `render_route` swaps the page on a history pop without going
    // through `guarded_navigate`, so the popstate handler must close the menu
    // itself or the panel outlives the page it was opened on.
    await page.goBack();
    await expect(page).toHaveURL(/\/configuration\/$/);
    await expect(page.locator('#brand-menu')).toBeHidden();
    await expect(menuButton).toHaveAttribute('aria-expanded', 'false');
  });
});
