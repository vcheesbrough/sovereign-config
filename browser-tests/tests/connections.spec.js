const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  grpcFrame,
  requestPermissions,
  mockValues,
  mockApplication,
  CONNECTION_ID,
  APP_PASSWORD_SENTINEL,
  mockConnections,
  openCallback,
  TREE_VALUES,
  treeNode,
  openConfiguration
} = require('./helpers');

test.describe('connections', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('access URLs are listed and created at the selected tree node', async ({ page }) => {
    const connections = await mockConnections(page, {
      connections: [{ id: CONNECTION_ID, name: 'Pipeline reader', root: '/apps/api' }]
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();

    await expect(page.locator('#path-connection-count')).toHaveText('1 connection');
    await expect(page.locator('#path-connections-body')).toContainText('Pipeline reader');

    // A sibling path shows none of it, and offers its own root instead.
    await treeNode(page, '/apps/worker').click();
    await expect(page.locator('#path-connection-count')).toHaveText('0 connections');
    await expect(page.locator('#empty-path-connections')).toBeVisible();
    await expect(page.locator('#path-connection-root')).toHaveText('/apps/worker');

    // A draft must not follow the operator to another namespace: it would be
    // armed to grant standing access to a root it was never aimed at.
    await page.locator('#path-connection-name').fill('Half-typed draft');
    await page.locator('#path-connection-permission-manage').check();
    await treeNode(page, '/apps/api').click();
    await treeNode(page, '/apps/worker').click();
    await expect(page.locator('#path-connection-name')).toHaveValue('');
    await expect(page.locator('#path-connection-permission-manage')).not.toBeChecked();
    await expect(page.locator('#path-connection-permission-read')).toBeChecked();

    await page.locator('#path-connection-name').fill('Worker reader');
    await page.getByRole('button', { name: 'Create access URL here' }).click();
    const confirmation = page.locator('#create-connection-dialog');
    await expect(confirmation).toBeVisible();
    // The selected node is the root; no root was typed anywhere.
    await expect(confirmation.locator('#create-connection-root')).toHaveText('/apps/worker');
    await confirmation.locator('#confirm-create-connection').click();

    await expect(page.locator('#connection-url-dialog')).toBeVisible();
    const created = connections.requests.find(request => request.method === 'CreateManagedConnection');
    expect(created.fields.get(1)).toBe('Worker reader');
    expect(created.fields.get(2)).toBe('/apps/worker');
    await page.locator('#close-connection-url').click();

    await expect(page.locator('#path-connection-count')).toHaveText('1 connection');
    await expect(page.locator('#path-connection-name')).toHaveValue('');
    // The tree now marks the path the new access URL is rooted at.
    await expect(treeNode(page, '/apps/worker').locator('.tree-key')).toHaveCount(1);

    // Rotating returns focus to the row it started from, not to the estate-wide
    // heading, which lives on the hidden Access URLs page.
    await page.locator('#path-rotate-connection-0').click();
    await page.locator('#confirm-rotate-connection').click();
    await expect(page.locator('#connection-url-dialog')).toBeVisible();
    await page.locator('#close-connection-url').click();
    await expect(page.locator('#path-rotate-connection-0')).toBeFocused();

    // Revoking from the same panel removes both the row and the key, and falls
    // back to this table's own heading because the row is gone.
    await page.locator('#path-revoke-connection-0').click();
    await page.locator('#confirm-revoke-connection').click();
    await expect(page.locator('#path-connection-count')).toHaveText('0 connections');
    await expect(page.locator('#path-connections-heading')).toBeFocused();
    await expect(treeNode(page, '/apps/worker').locator('.tree-key')).toHaveCount(0);
  });

  test('a path-scoped access URL requires a name and a permission', async ({ page }) => {
    const connections = await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/worker').click();

    await page.getByRole('button', { name: 'Create access URL here' }).click();
    await expect(page.locator('#create-connection-dialog')).toBeHidden();
    await expect(page.locator('#path-connection-name-error')).toBeVisible();

    await page.locator('#path-connection-name').fill('Worker reader');
    await page.locator('#path-connection-permission-read').uncheck();
    await page.getByRole('button', { name: 'Create access URL here' }).click();
    await expect(page.locator('#create-connection-dialog')).toBeHidden();
    await expect(page.locator('#path-connection-permissions-error')).toBeVisible();

    expect(connections.requests.map(request => request.method))
      .not.toContain('CreateManagedConnection');
  });

  test('a failed access-URL listing is reported rather than shown as none', async ({ page }) => {
    await mockConnections(page, {
      connections: [{ id: CONNECTION_ID, name: 'Pipeline reader', root: '/apps/api' }]
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();
    await expect(page.locator('#path-connection-count')).toHaveText('1 connection');
    await expect(treeNode(page, '/apps/api').locator('.tree-key')).toHaveCount(1);

    // The listing now fails. An empty panel would read as authoritative and could
    // prompt a second, redundant credential for a root that already has one.
    await page.route('**/sovereign.config.v3.ManagedConnections/ListManagedConnections', route =>
      route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(Buffer.alloc(0), 14)
      }));
    await treeNode(page, '/apps/worker').click();
    await treeNode(page, '/apps/api').click();

    await expect(page.locator('#path-connection-count')).toHaveText('Access URLs unavailable');
    await expect(page.locator('#path-connections-body')).toContainText('Pipeline reader');
    // The tree itself still renders, markers and all.
    await expect(page.getByRole('tree').getByRole('treeitem')).toHaveCount(5);
    await expect(treeNode(page, '/apps/api').locator('.tree-key')).toHaveCount(1);
  });

  test('managed connections list only manageable roots and are accessible', async ({ page }) => {
    const connections = await mockConnections(page, {
      connections: [
        { id: CONNECTION_ID, name: 'Pipeline reader', root: '/apps/api', state: 2 },
        { id: 'b1b2c3d4e5f6a7b8b1b2c3d4e5f6a7b8', name: 'Recovering', root: '/apps/web', state: 3 }
      ]
    });
    await openCallback(page);
    await openView(page, 'Access URLs');

    await expect(page.locator('#connection-count')).toHaveText('2 connections');
    await expect(page.getByRole('rowheader', { name: 'Pipeline reader' })).toBeVisible();
    await expect(page.getByRole('cell', { name: '/apps/api' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Rotation unknown' })).toBeVisible();
    // External identities must never reach the browser.
    await expect(page.locator('body')).not.toContainText('sc-managed-');

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
    expect(connections.requests.map(request => request.method))
      .toContain('ListManagedConnections');
  });

  test('creating a connection confirms the exact root and reveals the URL once', async ({ page }) => {
    const connections = await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('/apps/api');
    // Read is selected by default; also grant write for this URL.
    await page.locator('#connection-permissions').getByLabel('Write').check();
    await page.getByRole('button', { name: 'Create access URL' }).click();

    // The confirmation names the exact root and the selected grant.
    const confirmation = page.locator('#create-connection-dialog');
    await expect(confirmation).toBeVisible();
    await expect(confirmation).toContainText('/apps/api');
    await expect(confirmation).toContainText('read and write');
    await expect(page.locator('#cancel-create-connection')).toBeFocused();

    await confirmation.getByRole('button', { name: 'Create access URL' }).click();

    // The result surface opens masked; no secret is in the DOM yet.
    const result = page.locator('#connection-url-dialog');
    await expect(result).toBeVisible();
    await expect(page.locator('#connection-url-mask')).toBeVisible();
    await expect(page.locator('#revealed-connection-url')).toBeHidden();
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);
    await expect(page.locator('#reveal-connection-url')).toHaveAttribute('aria-expanded', 'false');

    // Reveal is explicit and keyboard reachable.
    await expect(page.locator('#reveal-connection-url')).toBeFocused();
    await page.keyboard.press('Enter');
    const revealed = page.locator('#revealed-connection-url');
    await expect(revealed).toBeVisible();
    await expect(revealed).toHaveAttribute('readonly', '');
    await expect(revealed).toBeFocused();
    await expect(page.locator('#reveal-connection-url')).toHaveAttribute('aria-expanded', 'true');
    expect(await revealed.inputValue()).toContain('client_secret=');

    const created = connections.requests.find(request => request.method === 'CreateManagedConnection');
    expect(created.fields.get(1)).toBe('Pipeline reader');
    expect(created.fields.get(2)).toBe('/apps/api');
    // Field 3 carries the selected permission enums (READ=1, WRITE=2).
    expect(requestPermissions(created)).toEqual([1, 2]);

    // The listed row shows the granted permissions.
    await page.locator('#close-connection-url').click();
    await expect(page.getByRole('cell', { name: 'Read, Write', exact: true })).toBeVisible();
  });

  test('the one-time connection URL is discarded and never persisted', async ({ page }) => {
    await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');
    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('/apps/api');
    await page.getByRole('button', { name: 'Create access URL' }).click();
    await page.locator('#confirm-create-connection').click();
    await page.locator('#reveal-connection-url').click();
    await expect(page.locator('#revealed-connection-url')).toBeVisible();

    await page.locator('#close-connection-url').click();

    // Closing discards the value from application state and the DOM.
    await expect(page.locator('#connection-url-dialog')).toBeHidden();
    expect(await page.locator('#revealed-connection-url').inputValue()).toBe('');
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);

    // The secret must never reach history, storage, or caches.
    const leaked = await page.evaluate(async sentinel => {
      const stores = [];
      for (const storage of [localStorage, sessionStorage]) {
        for (let index = 0; index < storage.length; index++) {
          stores.push(String(storage.getItem(storage.key(index))));
        }
      }
      if (globalThis.caches) {
        for (const key of await caches.keys()) {
          const cache = await caches.open(key);
          for (const request of await cache.keys()) stores.push(request.url);
        }
      }
      return {
        storage: stores.some(entry => entry.includes(sentinel)),
        url: location.href.includes(sentinel),
        registrations: Boolean(navigator.serviceWorker
          && (await navigator.serviceWorker.getRegistrations()).length)
      };
    }, APP_PASSWORD_SENTINEL);
    expect(leaked.storage).toBe(false);
    expect(leaked.url).toBe(false);
    expect(leaked.registrations).toBe(false);

    // Reloading must not restore the one-time URL.
    await page.reload();
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);
  });

  test('rotation and revocation confirm destructively and discard secrets', async ({ page }) => {
    const connections = await mockConnections(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByRole('button', { name: 'Rotate credential for Pipeline reader' }).click();
    const rotateDialog = page.locator('#rotate-connection-dialog');
    await expect(rotateDialog).toBeVisible();
    await expect(rotateDialog).toContainText('Pipeline reader');
    await expect(rotateDialog).toContainText('stops working immediately');
    // The confirmation must not disclose any credential or provider identity.
    await expect(rotateDialog).not.toContainText('sc-managed-');
    await expect(rotateDialog).not.toContainText('client_secret');

    await page.locator('#confirm-rotate-connection').click();
    await expect(page.locator('#connection-url-dialog')).toBeVisible();
    await page.locator('#reveal-connection-url').click();
    expect(await page.locator('#revealed-connection-url').inputValue()).toContain('client_secret=');
    await page.locator('#close-connection-url').click();
    expect(await page.locator('#revealed-connection-url').inputValue()).toBe('');

    await page.getByRole('button', { name: 'Revoke Pipeline reader' }).click();
    const revokeDialog = page.locator('#revoke-connection-dialog');
    await expect(revokeDialog).toBeVisible();
    await expect(revokeDialog).toContainText('cannot be restored');
    await expect(revokeDialog).not.toContainText('sc-managed-');
    await page.locator('#confirm-revoke-connection').click();

    await expect(page.locator('#connection-state')).toHaveText('Connection revoked');
    await expect(page.locator('#connection-count')).toHaveText('0 connections');
    expect(connections.requests.map(request => request.method)).toContain('RotateManagedConnection');
    expect(connections.requests.map(request => request.method)).toContain('RevokeManagedConnection');
  });

  test('cancelling a confirmation restores focus and performs no operation', async ({ page }) => {
    const connections = await mockConnections(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByRole('button', { name: 'Rotate credential for Pipeline reader' }).click();
    await page.locator('#cancel-rotate-connection').click();

    await expect(page.locator('#rotate-connection-dialog')).toBeHidden();
    await expect(page.locator('#rotate-connection-0')).toBeFocused();
    expect(connections.requests.map(request => request.method))
      .not.toContain('RotateManagedConnection');
  });

  test('ambiguous rotation reports a bounded error and returns no URL', async ({ page }) => {
    await mockConnections(page, { script: { RotateManagedConnection: 14 } });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByRole('button', { name: 'Rotate credential for Pipeline reader' }).click();
    await page.locator('#confirm-rotate-connection').click();

    await expect(page.locator('#error')).toHaveText('service is unavailable');
    await expect(page.locator('#connection-url-dialog')).toBeHidden();
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);
    // A failed rotation leaves the row in place, so focus returns to the control
    // that started it rather than to the heading above it.
    await expect(page.locator('#rotate-connection-0')).toBeFocused();
  });

  test('a conflicting rotation reports the bounded in-progress error', async ({ page }) => {
    await mockConnections(page, { script: { RotateManagedConnection: 10 } });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByRole('button', { name: 'Rotate credential for Pipeline reader' }).click();
    await page.locator('#confirm-rotate-connection').click();

    await expect(page.locator('#error')).toHaveText('service is unavailable');
    await expect(page.locator('#connection-url-dialog')).toBeHidden();
  });

  test('connection inputs validate before any confirmation opens', async ({ page }) => {
    const connections = await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByLabel('Display name').fill('');
    await page.getByLabel('Root').fill('/apps/api');
    await page.getByRole('button', { name: 'Create access URL' }).click();
    await expect(page.locator('#create-connection-dialog')).toBeHidden();
    await expect(page.locator('#connection-name')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('#connection-name-error')).toBeVisible();

    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('bad_root');
    await page.getByRole('button', { name: 'Create access URL' }).click();
    await expect(page.locator('#create-connection-dialog')).toBeHidden();
    await expect(page.locator('#connection-root')).toHaveAttribute('aria-invalid', 'true');

    expect(connections.requests.map(request => request.method))
      .not.toContain('CreateManagedConnection');
  });

  test('creating an access URL requires at least one permission', async ({ page }) => {
    const connections = await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('/apps/api');
    // Clear the default Read selection so nothing is granted.
    await page.locator('#connection-permissions').getByLabel('Read').uncheck();
    await page.getByRole('button', { name: 'Create access URL' }).click();

    await expect(page.locator('#create-connection-dialog')).toBeHidden();
    await expect(page.locator('#connection-permissions-error')).toBeVisible();
    expect(connections.requests.map(request => request.method))
      .not.toContain('CreateManagedConnection');

    // Selecting Manage alone unblocks creation and grants exactly that.
    await page.locator('#connection-permissions').getByLabel('Manage').check();
    await page.getByRole('button', { name: 'Create access URL' }).click();
    const confirmation = page.locator('#create-connection-dialog');
    await expect(confirmation).toBeVisible();
    await expect(confirmation).toContainText('manage');
    await confirmation.getByRole('button', { name: 'Create access URL' }).click();

    await expect(page.locator('#connection-url-dialog')).toBeVisible();
    const created = connections.requests.find(request => request.method === 'CreateManagedConnection');
    expect(requestPermissions(created)).toEqual([3]);
  });

  test('the access URLs view is renamed and lists granted permissions', async ({ page }) => {
    await mockConnections(page, {
      connections: [{ name: 'Pipeline reader', root: '/apps/api', permissions: [1, 2, 3] }]
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');

    await expect(page.getByRole('heading', { name: 'Access URLs' })).toBeVisible();
    // The menu marks the view the operator is already on.
    await page.getByRole('button', { name: 'Sovereign Config' }).click();
    const link = page.getByRole('link', { name: 'Access URLs', exact: true });
    await expect(link).toBeVisible();
    await expect(link).toHaveClass('active');
    await expect(page.getByRole('cell', { name: 'Read, Write, Manage', exact: true })).toBeVisible();
  });

  test('logout discards a revealed connection URL and clears the view', async ({ page }) => {
    await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');
    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('/apps/api');
    await page.getByRole('button', { name: 'Create access URL' }).click();
    await page.locator('#confirm-create-connection').click();
    await page.locator('#reveal-connection-url').click();
    await expect(page.locator('#revealed-connection-url')).toBeVisible();

    // The modal correctly blocks pointer access to the page behind it, so the
    // event is dispatched directly to prove the state-clearing path.
    await page.locator('#logout').dispatchEvent('click');

    await expect(page.locator('#connection-url-dialog')).toBeHidden();
    expect(await page.locator('#revealed-connection-url').inputValue()).toBe('');
    await expect(page.locator('#connection-count')).toHaveText('0 connections');
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);
  });

  // Regression: a create that succeeds while the user logs out before its own
  // reload of the connections list resolves must not resurrect the one-time
  // URL dialog once that reload finally completes.
  test('a logout while create is still reloading connections suppresses the URL dialog', async ({ page }) => {
    const connections = await mockConnections(page, { connections: [] });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');
    await expect(page.locator('#connection-count')).toHaveText('0 connections');

    await page.getByLabel('Display name').fill('Pipeline reader');
    await page.getByLabel('Root').fill('/apps/api');
    await page.getByRole('button', { name: 'Create access URL' }).click();

    const releaseList = connections.delayNextList();
    await page.locator('#confirm-create-connection').click();

    // Create has succeeded; its own reload of the connections list is now
    // blocked. Log out before that reload completes.
    await page.locator('#logout').dispatchEvent('click');
    releaseList();

    // The dialog must not resurrect the just-provisioned credential after
    // logout, even though the reload that unblocks it finishes afterward.
    await expect(page.locator('#connection-url-dialog')).toBeHidden();
    await expect(page.locator('body')).not.toContainText(APP_PASSWORD_SENTINEL);
  });

  test('the Authentik administration endpoint is absent from browser assets', async ({ page }) => {
    const responses = [];
    page.on('response', response => responses.push(response));
    await mockConnections(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await page.goto('/connections/');
    await expect(page.locator('#connection-count')).toHaveText('1 connection');

    for (const response of responses) {
      if (!response.url().startsWith('http://127.0.0.1:8088')) continue;
      let body;
      try {
        body = await response.text();
      } catch {
        continue;
      }
      expect(body).not.toContain('/api/v3/core/users/');
      expect(body).not.toContain('manager-api-token');
      expect(body).not.toContain('set_key');
    }
  });
});
