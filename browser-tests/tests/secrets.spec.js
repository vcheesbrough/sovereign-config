const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  grpcFrame,
  mockValues,
  mockApplication,
  openCallback
} = require('./helpers');

test.describe('secrets', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('secret values stay masked, rotate explicitly, and survive JSON edits', async ({ page }) => {
    const originalSecret = 'original-browser-secret-sentinel';
    const rotatedSecret = 'rotated-browser-secret-sentinel';
    const addedSecret = 'added-browser-secret-sentinel';
    const unsubmittedSecret = 'unsubmitted-browser-secret-sentinel';
    const consoleMessages = [];
    const pageErrors = [];
    page.on('console', message => consoleMessages.push(message.text()));
    page.on('pageerror', error => pageErrors.push(error.message));

    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/apps/api/api-token': { value: originalSecret, secret: true },
      '/apps/api/enabled': 'true'
    });
    await page.goto('/configuration/apps/api');

    // A secret is one padlocked box: redacted and empty until the lock is
    // opened, and the same box a replacement is typed into.
    const row = page.getByRole('row', { name: /api-token/ });
    const secret = page.getByLabel('Secret value for api-token');
    await expect(secret).toHaveAttribute('type', 'password');
    await expect(secret).toHaveAttribute('placeholder', '********');
    await expect(secret).toHaveValue('');
    await expect(page.locator('body')).not.toContainText(originalSecret);

    const padlock = row.getByRole('button', { name: 'Reveal secret for api-token' });
    await padlock.focus();
    await page.keyboard.press('Enter');
    await expect(secret).toHaveValue(originalSecret);
    await expect(secret).toHaveAttribute('type', 'text');
    const opened = row.getByRole('button', { name: 'Hide secret for api-token' });
    await expect(opened).toHaveAttribute('aria-pressed', 'true');

    // Shutting the lock discards the plaintext rather than merely re-masking it.
    await opened.focus();
    await page.keyboard.press('Enter');
    await expect(secret).toHaveValue('');
    await expect(secret).toHaveAttribute('type', 'password');
    await expect(page.locator('body')).not.toContainText(originalSecret);

    // Writing a replacement needs no reveal: the locked box takes it directly.
    await secret.fill(rotatedSecret);
    await row.getByRole('button', { name: 'Save api-token' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    expect(values.getValue('/apps/api/api-token')).toEqual({ value: rotatedSecret, secret: true });
    await expect(page.locator('body')).not.toContainText(rotatedSecret);

    // Named "Signing-Key"; per card #294 that case is established and retained
    // — including through the JSON round trip below, where the same key is
    // resubmitted lowercase and must still resolve to it without renaming it.
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Signing-Key');
    await page.getByLabel('Store as secret').check();
    const newSecret = page.getByLabel('Secret value', { exact: true });
    await expect(newSecret).toHaveAttribute('type', 'password');
    // The new-value row's padlock only unmasks what is being typed — there is no
    // stored secret behind it to fetch.
    const newPadlock = page.getByRole('button', { name: 'Show the secret being typed' });
    await newPadlock.click();
    await expect(newSecret).toHaveAttribute('type', 'text');
    await page.getByRole('button', { name: 'Hide the secret being typed' }).click();
    await expect(newSecret).toHaveAttribute('type', 'password');
    await newSecret.fill(addedSecret);
    await page.locator('#new-value-row').getByRole('button', { name: 'Save new value' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    expect(values.getValue('/apps/api/Signing-Key')).toEqual({ value: addedSecret, secret: true });
    await expect(page.locator('body')).not.toContainText(addedSecret);

    const mode = page.getByRole('switch', { name: 'JSON' });
    await mode.check();
    const editor = page.getByLabel('JSON subtree');
    await expect(editor).toHaveValue(
      '{\n  "api-token": "********",\n  "enabled": "true",\n  "Signing-Key": "********"\n}\n'
    );
    await expect(editor).not.toHaveValue(new RegExp(`${rotatedSecret}|${addedSecret}`));
    await editor.fill('{"api-token":"********","enabled":"false","signing-key":"********"}');
    await page.getByRole('button', { name: 'Save JSON' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    expect(values.getValue('/apps/api/api-token')).toEqual({ value: rotatedSecret, secret: true });
    // The established case survives a lowercase-keyed rewrite: rule 2 keeps the
    // display form put down by the first write.
    expect(values.getValue('/apps/api/Signing-Key')).toEqual({ value: addedSecret, secret: true });
    expect(values.getValue('/apps/api/enabled')).toEqual({ value: 'false', secret: false });

    await mode.uncheck();
    const refreshedRow = page.getByRole('row', { name: /api-token/ });
    await refreshedRow.getByRole('button', { name: 'Reveal secret for api-token' }).click();
    await expect(page.getByLabel('Secret value for api-token')).toHaveValue(rotatedSecret);

    const failedPut = '**/sovereign.config.v3.Configuration/PutValue';
    await page.route(failedPut, route => route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(Buffer.alloc(0), 7)
    }));
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Name', { exact: true }).fill('failed-value');
    await page.getByLabel('Value', { exact: true }).fill('never-stored');
    await page.locator('#new-value-row').getByRole('button', { name: 'Save new value' }).click();
    await expect(page.getByText('permission denied', { exact: true })).toBeVisible();
    // Any error shuts every padlock on the page.
    await expect(page.getByLabel('Secret value for api-token')).toHaveValue('');
    await expect(page.getByLabel('Secret value for api-token')).toHaveAttribute('type', 'password');
    await page.unroute(failedPut);
    await page.locator('#new-value-row').getByRole('button', { name: 'Cancel new value' }).click();

    await refreshedRow.getByRole('button', { name: 'Reveal secret for api-token' }).click();
    await expect(page.getByLabel('Secret value for api-token')).toHaveValue(rotatedSecret);
    await page.reload();
    await expect(page.getByRole('row', { name: /api-token/ })).toBeVisible();
    await expect(page.getByLabel('Secret value for api-token')).toHaveValue('');
    await expect(page.locator('body')).not.toContainText(rotatedSecret);

    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Name', { exact: true }).fill('unsubmitted-secret');
    await page.getByLabel('Store as secret').check();
    await page.getByLabel('Secret value', { exact: true }).fill(unsubmittedSecret);
    await openView(page, 'Downloads');
    // An unsubmitted secret is an unsaved value, so leaving now asks first.
    await page.locator('#discard-changes').click();
    await expect(page.locator('body')).not.toContainText(unsubmittedSecret);
    await page.goBack();
    await expect(page.getByRole('row', { name: /api-token/ })).toBeVisible();
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Store as secret').check();
    await expect(page.getByLabel('Secret value', { exact: true })).toHaveValue('');
    await page.locator('#new-value-row').getByRole('button', { name: 'Cancel new value' }).click();

    await page.getByRole('row', { name: /api-token/ })
      .getByRole('button', { name: 'Reveal secret for api-token' }).click();
    await expect(page.getByLabel('Secret value for api-token')).toHaveValue(rotatedSecret);
    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
    await expect(page.locator('body')).not.toContainText(rotatedSecret);
    expect(consoleMessages.join('\n')).not.toContain(originalSecret);
    expect(consoleMessages.join('\n')).not.toContain(rotatedSecret);
    expect(consoleMessages.join('\n')).not.toContain(addedSecret);
    expect(consoleMessages.join('\n')).not.toContain(unsubmittedSecret);
    expect(pageErrors.join('\n')).not.toContain(originalSecret);
    expect(pageErrors.join('\n')).not.toContain(rotatedSecret);
    expect(pageErrors.join('\n')).not.toContain(addedSecret);
    expect(pageErrors.join('\n')).not.toContain(unsubmittedSecret);

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });

  test('a stray Save on a locked, untouched secret does not blank the stored value', async ({ page }) => {
    const storedSecret = 'guarded-browser-secret-sentinel';
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/apps/api/api-token': { value: storedSecret, secret: true }
    });
    await page.goto('/configuration/apps/api');

    // The locked box reads as filled behind its placeholder but holds nothing;
    // the row's Save is otherwise indistinguishable from a plain row's.
    const row = page.getByRole('row', { name: /api-token/ });
    const secret = page.getByLabel('Secret value for api-token');
    await expect(secret).toHaveValue('');
    await row.getByRole('button', { name: 'Save api-token' }).click();

    await expect(page.getByText('type a replacement secret before saving')).toBeVisible();
    expect(values.requests.map(request => request.method)).not.toContain('PutValue');
    expect(values.getValue('/apps/api/api-token')).toEqual({ value: storedSecret, secret: true });
  });

  test('delayed secret reveals are discarded after configuration navigation', async ({ page }) => {
    const oldSecret = 'old-path-secret-sentinel';
    const newSecret = 'new-path-secret-sentinel';
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/apps/api/api-token': { value: oldSecret, secret: true },
      '/apps/worker/worker-token': { value: newSecret, secret: true }
    });
    await page.goto('/configuration/apps/api');
    await expect(page.getByRole('row', { name: /api-token/ })).toBeVisible();
    const releaseReveal = values.delayNextReveal();
    const revealResponse = page.waitForResponse(
      '**/sovereign.config.v3.Configuration/RevealSecret'
    );
    await page.getByRole('row', { name: /api-token/ })
      .getByRole('button', { name: 'Reveal secret for api-token' }).click();

    const pathInput = page.getByLabel('Selected path');
    await pathInput.fill('/apps/worker');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
    await expect(page.getByRole('row', { name: /worker-token/ })).toBeVisible();

    releaseReveal();
    await revealResponse;
    // The reply belongs to a path the operator has already left, so it is
    // dropped rather than poured into whichever field now sits in that row.
    await expect(page.getByLabel('Secret value for worker-token')).toHaveValue('');
    await expect(page.getByLabel('Secret value for worker-token')).toHaveAttribute('type', 'password');
    await expect(page.locator('body')).not.toContainText(oldSecret);
  });
});
