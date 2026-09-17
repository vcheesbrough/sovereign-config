const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  openView,
  mockApplication
} = require('./helpers');

test.describe('downloads', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  const INSTALLER = 'install-sovereign-config-cli-2.10.0-x86_64-linux.sh';

  async function mockManifest(page, installers) {
    await page.route('**/dist/manifest.json', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ installers })
    }));
  }

  test('downloads page lists the published installer with a run command', async ({ page }) => {
    await mockApplication(page);
    await mockManifest(page, [
      { file: INSTALLER, checksum: `${INSTALLER}.sha256`, size: 2921310 }
    ]);
    await page.goto('/');
    await openView(page, 'Downloads');
    await expect(page).toHaveURL(/\/downloads$/);
    await expect(page.getByRole('heading', { name: 'Downloads', level: 1 })).toBeVisible();

    await expect(page.getByRole('heading', { name: INSTALLER })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Download installer' }))
      .toHaveAttribute('href', `/dist/${INSTALLER}`);
    await expect(page.getByRole('link', { name: 'sha256' }))
      .toHaveAttribute('href', `/dist/${INSTALLER}.sha256`);
    await expect(page.getByText(/curl -fsSL/)).toBeVisible();
    await expect(page.getByText(/mktemp -d/)).toBeVisible();
    // The command aborts on a failed download rather than running a partial file.
    await expect(page.getByText(/set -e/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy command' })).toBeVisible();

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });

  test('downloads page shows an empty state when no installers are published', async ({ page }) => {
    await mockApplication(page);
    await mockManifest(page, []);
    await page.goto('/');
    await openView(page, 'Downloads');
    await expect(page.getByText('No installers are published by this server.')).toBeVisible();
  });
});
