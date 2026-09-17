const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  mutationSequence,
  grpcFrame,
  mockValues,
  mockApplication,
  openCallback
} = require('./helpers');

test.describe('values', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('JSON mode reads and replaces subtrees without exposing row deletion', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const { requests } = await mockValues(page, {
      '/apps/api/enabled': 'true',
      '/apps/api/nested/message': 'hello\nworld',
      '/apps/worker/concurrency': '4',
      '/foo/foo2/foo3/deepvalue': 'deepvalue',
      '/foo/second/abc': 'bar'
    });
    await page.goto('/configuration/apps/api');

    const mode = page.getByRole('switch', { name: 'JSON' });
    await expect(mode).not.toBeChecked();
    await mode.check();
    await expect(page.getByRole('button', { name: 'Add value' })).toBeHidden();
    await expect(page.getByRole('button', { name: /^Delete / })).toHaveCount(0);
    const editor = page.getByLabel('JSON subtree');
    await expect(editor).toHaveValue(
      '{\n  "enabled": "true",\n  "nested": {\n    "message": "hello\\nworld"\n  }\n}\n'
    );

    const beforeInvalid = requests.length;
    await editor.fill('{"enabled":true}');
    await expect(editor).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('configuration JSON is invalid')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save JSON' })).toBeDisabled();
    expect(requests).toHaveLength(beforeInvalid);

    await editor.fill('{"enabled":"false","new-value":"new"}');
    await page.getByRole('button', { name: 'Save JSON' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    await expect(editor).toHaveValue(
      '{\n  "enabled": "false",\n  "new-value": "new"\n}\n'
    );
    // A save re-reads the edited subtree, then the sidebar tree re-reads the root
    // so a namespace the save created or emptied appears or disappears.
    expect(requests.slice(-3).map(request => request.method)).toEqual([
      'ReplaceSubTree', 'GetSubTree', 'GetSubTree'
    ]);
    expect(requests.slice(-2).map(request => request.fields.get(1))).toEqual(['/apps/api', '/']);

    const pathInput = page.getByLabel('Selected path');
    await pathInput.fill('/apps/api/enabled');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(editor).toHaveValue('"false"\n');
    await editor.fill('"exact-json"');
    await page.getByRole('button', { name: 'Save JSON' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    await expect(editor).toHaveValue('"exact-json"\n');
    await page.goBack();
    await expect(editor).toHaveValue(
      '{\n  "enabled": "exact-json",\n  "new-value": "new"\n}\n'
    );

    await mode.uncheck();
    await expect(page.getByLabel('Value for enabled')).toHaveValue('exact-json');
    await expect(page.getByLabel('Value for new-value')).toHaveValue('new');
    await expect(page.getByText('message', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add value' })).toBeVisible();

    await mode.check();
    await pathInput.fill('/apps/worker');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
    await expect(mode).toBeChecked();
    await expect(editor).toHaveValue(
      '{\n  "concurrency": "4"\n}\n'
    );

    await pathInput.fill('/foo/foo2/foo3');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(editor).toHaveValue('{\n  "deepvalue": "deepvalue"\n}\n');

    await pathInput.fill('/foo/s');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(editor).toHaveValue('{}\n');
    await editor.fill('{"child":"value"}');
    await page.getByRole('button', { name: 'Save JSON' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    await pathInput.fill('/foo/second');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(editor).toHaveValue('{\n  "abc": "bar"\n}\n');

    await pathInput.fill('/apps/empty');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(editor).toHaveValue('{}\n');
    await pathInput.fill('/');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect.poll(() => editor.inputValue()).toContain('"apps": {');
    await expect.poll(() => editor.inputValue()).toContain('"concurrency": "4"');
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });

  test('JSON mode retains rejected edits and reports non-representable stored trees', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/collision': 'parent',
      '/collision/child': 'child',
      '/valid/value': 'before'
    });
    await page.goto('/configuration/collision');
    await expect(page.getByLabel('Value for child')).toHaveValue('child');
    const mode = page.getByRole('switch', { name: 'JSON' });
    await mode.check();
    await expect(page.getByText('configuration subtree cannot be represented as JSON')).toBeVisible();

    const pathInput = page.getByLabel('Selected path');
    const releaseSubtree = values.delayNextSubtree();
    await pathInput.fill('/valid');
    await page.getByRole('button', { name: 'Open' }).click();
    const editor = page.getByLabel('JSON subtree');
    const rejected = '{"value":"after"}';
    await editor.fill(rejected);
    const subtreeResponse = page.waitForResponse(
      '**/sovereign.config.v3.Configuration/GetSubTree'
    );
    releaseSubtree();
    await subtreeResponse;
    await expect(editor).toHaveValue(rejected);
    await page.route('**/sovereign.config.v3.Configuration/ReplaceSubTree', route => route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(Buffer.alloc(0), 7)
    }));
    await page.getByRole('button', { name: 'Save JSON' }).click();
    await expect(page.getByText('permission denied', { exact: true })).toBeVisible();
    await expect(editor).toHaveValue(rejected);
    await expect(page.getByRole('button', { name: 'Save JSON' })).toBeEnabled();
  });

  test('path and new-value fields validate on every keystroke', async ({ page }) => {
    await openCallback(page);
    await mockValues(page);
    await openView(page, 'Configuration values');
    const pathInput = page.getByLabel('Selected path');

    await pathInput.fill('apps/unrooted-path');
    await expect(pathInput).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('path must begin with / and contain only letters, numbers, hyphens, and underscores')).toBeVisible();
    await expect(page).toHaveURL(/\/configuration\/$/);

    await pathInput.fill('/apps/bad.path');
    await expect(pathInput).toHaveAttribute('aria-invalid', 'true');

    // `_` is a legal segment character since 2.15.0.
    await pathInput.fill('/apps/github_token');
    await expect(pathInput).toHaveAttribute('aria-invalid', 'false');

    await pathInput.fill('/apps/new-area');
    await expect(pathInput).toHaveAttribute('aria-invalid', 'false');
    await page.getByRole('button', { name: 'Open' }).click();
    await expect(page).toHaveURL(/\/configuration\/apps\/new-area$/);
    await expect(page.getByText('No values at this path.')).toBeVisible();

    await page.getByRole('button', { name: 'Add value' }).click();
    const name = page.getByLabel('Name', { exact: true });
    await name.fill('bad.name');
    await expect(name).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('Name must contain only letters, numbers, hyphens, and underscores')).toBeVisible();
    await name.fill('github_token');
    await expect(name).toHaveAttribute('aria-invalid', 'false');
    await name.fill('Feature-Flag');
    await expect(name).toHaveAttribute('aria-invalid', 'false');

    const value = page.getByLabel('Value', { exact: true });
    await value.evaluate(element => {
      element.value = `bad\u0000value`;
      element.dispatchEvent(new InputEvent('input', { bubbles: true }));
    });
    await expect(value).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('Value cannot contain a null character')).toBeVisible();
  });

  test('grid adds, edits, and permanently deletes individual values', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const { requests } = await mockValues(page);
    await page.goto('/configuration/apps/api');
    await expect(page.getByText('No values at this path.')).toBeVisible();

    // The name is typed as "Feature-Flag" and, per card #294, that case is
    // established and retained end to end: in the request, the field label,
    // and the delete confirmation — not folded to lowercase.
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Feature-Flag');
    await page.getByLabel('Value', { exact: true }).fill('plain-value-sentinel');
    await page.locator('#new-value-row').getByRole('button', { name: 'Save new value' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    const editor = page.getByLabel('Value for Feature-Flag');
    await expect(editor).toHaveValue('plain-value-sentinel');
    const put = requests.find(request => request.method === 'PutValue');
    expect(put.fields.get(1)).toBe('/apps/api/Feature-Flag');
    expect(put.fields.get(2)).toBe('plain-value-sentinel');

    await editor.fill('updated-value-sentinel');
    await page.getByRole('row', { name: /feature-flag/i })
      .getByRole('button', { name: 'Save Feature-Flag' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Value for Feature-Flag')).toHaveValue('updated-value-sentinel');

    const row = page.getByRole('row', { name: /feature-flag/i });
    const remove = row.getByRole('button', { name: 'Delete' });
    await remove.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('/apps/api/Feature-Flag')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(remove).toBeFocused();

    await remove.click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('Deleted', { exact: true })).toBeVisible();
    await expect(page.getByText('No values at this path.')).toBeVisible();
    expect(mutationSequence(requests))
      .toEqual(['PutValue', 'ListValues', 'PutValue', 'ListValues', 'DeleteValues', 'ListValues']);
  });

  test('grid lists every alias path and removes one without deleting the value', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const { requests } = await mockValues(page, {
      '/apps/api/feature-flag': {
        value: 'aliased-value-sentinel',
        aliases: ['/apps/api/legacy-flag', '/shared/feature-flag']
      }
    });
    await page.goto('/configuration/apps/api');

    const row = page.getByRole('row', { name: /feature-flag/ });
    await expect(row.getByText('/apps/api/feature-flag', { exact: true })).toBeVisible();
    await expect(row.getByText('/apps/api/legacy-flag', { exact: true })).toBeVisible();
    await expect(row.getByText('/shared/feature-flag', { exact: true })).toBeVisible();

    const removeLegacy = row.getByRole('button', { name: 'Remove path /apps/api/legacy-flag' });
    await removeLegacy.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('/apps/api/legacy-flag')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(removeLegacy).toBeFocused();

    await removeLegacy.click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('Deleted', { exact: true })).toBeVisible();

    const deletions = requests.filter(request => request.method === 'DeleteValues');
    expect(deletions).toHaveLength(1);
    expect(deletions[0].fields.get(1)).toBe('/apps/api/legacy-flag');
    expect(deletions[0].fields.get(2)).toBeUndefined();

    const refreshedRow = page.getByRole('row', { name: /feature-flag/ });
    await expect(refreshedRow.getByText('/apps/api/feature-flag', { exact: true })).toBeVisible();
    await expect(refreshedRow.getByText('/shared/feature-flag', { exact: true })).toBeVisible();
    await expect(refreshedRow.getByText('/apps/api/legacy-flag', { exact: true })).toHaveCount(0);
    await expect(page.getByLabel('Value for feature-flag')).toHaveValue('aliased-value-sentinel');
    expect(mutationSequence(requests)).toEqual(['DeleteValues', 'ListValues']);
  });

  test('grid adds another path to an existing value', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const { requests } = await mockValues(page, {
      '/apps/api/feature-flag': { value: 'aliased-value-sentinel' }
    });
    await page.goto('/configuration/apps/api');

    const row = page.getByRole('row', { name: /feature-flag/ });
    await expect(row.getByText('/apps/worker/feature-flag', { exact: true })).toHaveCount(0);

    const addPath = row.getByRole('button', { name: 'Add a path to feature-flag' });
    await addPath.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('/apps/api/feature-flag')).toBeVisible();
    await expect(page.getByLabel('New absolute path')).toBeFocused();

    // A malformed path is rejected in the dialog without issuing an RPC.
    await page.getByLabel('New absolute path').fill('worker/feature-flag');
    await page.getByRole('button', { name: 'Add path', exact: true }).click();
    await expect(dialog).toBeVisible();
    await expect(page.getByText('Enter an absolute path such as /apps/worker/database-url.')).toBeVisible();
    expect(requests.filter(request => request.method === 'AddValuePath')).toHaveLength(0);

    // Cancelling returns focus to the control that opened the dialog.
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(addPath).toBeFocused();

    await addPath.click();
    await page.getByLabel('New absolute path').fill('/apps/worker/feature-flag');
    await page.getByRole('button', { name: 'Add path', exact: true }).click();
    await expect(page.getByText('Path added', { exact: true })).toBeVisible();

    const additions = requests.filter(request => request.method === 'AddValuePath');
    expect(additions).toHaveLength(1);
    expect(additions[0].fields.get(1)).toBe('/apps/api/feature-flag');
    expect(additions[0].fields.get(2)).toBe('/apps/worker/feature-flag');

    const refreshedRow = page.getByRole('row', { name: /feature-flag/ });
    await expect(refreshedRow.getByText('/apps/api/feature-flag', { exact: true })).toBeVisible();
    await expect(refreshedRow.getByText('/apps/worker/feature-flag', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Value for feature-flag')).toHaveValue('aliased-value-sentinel');
    // The sidebar tree's own whole-estate read is a separate concern; what
    // matters here is that the flow performed exactly one aliasing mutation.
    expect(mutationSequence(requests)).toEqual(['AddValuePath', 'ListValues']);
  });

  test('a second add-path activation while the request is in flight is ignored', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    const values = await mockValues(page, {
      '/apps/api/feature-flag': { value: 'aliased-value-sentinel' }
    });
    await page.goto('/configuration/apps/api');

    const row = page.getByRole('row').filter({ has: page.getByLabel('Value for feature-flag') });
    await row.getByRole('button', { name: 'Add a path to feature-flag' }).click();
    await page.getByLabel('New absolute path').fill('/apps/worker/feature-flag');

    // Hold the RPC open so both activations land while it is still in flight. A
    // duplicate would create the path once and then report the second request's
    // conflict, showing an error for a mutation that actually succeeded.
    const release = values.delayNextAddPath();
    const confirm = page.getByRole('button', { name: 'Add path', exact: true });
    await confirm.click();
    await expect(confirm).toBeDisabled();
    await confirm.click({ force: true });
    release();

    await expect(page.getByText('Path added', { exact: true })).toBeVisible();
    expect(values.requests.filter(request => request.method === 'AddValuePath')).toHaveLength(1);
    await expect(page.locator('#error')).toBeHidden();
    const refreshed = page.getByRole('row').filter({ has: page.getByLabel('Value for feature-flag') });
    await expect(refreshed.getByText('/apps/worker/feature-flag', { exact: true })).toBeVisible();
  });

  // Two paths of one value can both sit directly under the selected namespace.
  // A namespace listing enumerates the paths that live in it, so both appear as
  // their own row rather than one being collapsed into the other's alias list:
  // hiding either would omit a real, authorized path from its own namespace and
  // leave which one survives decided by sort order.
  test('sibling paths of one value each keep their own grid row', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {
      '/apps/api/feature-flag': {
        value: 'shared-value-sentinel',
        aliases: ['/apps/api/legacy-flag']
      },
      '/apps/api/legacy-flag': {
        value: 'shared-value-sentinel',
        aliases: ['/apps/api/feature-flag']
      }
    });
    await page.goto('/configuration/apps/api');

    const canonical = page.getByRole('row').filter({ has: page.getByLabel('Value for feature-flag') });
    const sibling = page.getByRole('row').filter({ has: page.getByLabel('Value for legacy-flag') });
    await expect(canonical).toHaveCount(1);
    await expect(sibling).toHaveCount(1);

    // Each row is anchored on its own path and names the other as an alias.
    await expect(canonical.getByText('/apps/api/feature-flag', { exact: true })).toBeVisible();
    await expect(canonical.getByText('/apps/api/legacy-flag', { exact: true })).toBeVisible();
    await expect(sibling.getByText('/apps/api/legacy-flag', { exact: true })).toBeVisible();
    await expect(sibling.getByText('/apps/api/feature-flag', { exact: true })).toBeVisible();

    // Both resolve to the same stored value, and both stay independently operable.
    await expect(page.getByLabel('Value for feature-flag')).toHaveValue('shared-value-sentinel');
    await expect(page.getByLabel('Value for legacy-flag')).toHaveValue('shared-value-sentinel');
    await expect(canonical.getByRole('button', { name: 'Add a path to feature-flag' })).toBeVisible();
    await expect(sibling.getByRole('button', { name: 'Add a path to legacy-flag' })).toBeVisible();
    await expect(page.getByText('2 values')).toBeVisible();
  });

  test('trailers-only save errors retain their bounded gRPC status', async ({ page }) => {
    await openCallback(page);
    await mockValues(page);
    await page.route('**/sovereign.config.v3.Configuration/PutValue', route => route.fulfill({
      status: 200,
      headers: {
        'content-type': 'application/grpc-web+proto',
        'grpc-status': '7'
      },
      body: Buffer.alloc(0)
    }));

    await openView(page, 'Configuration values');
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByLabel('Name', { exact: true }).fill('foo');
    await page.getByLabel('Value', { exact: true }).fill('bar');
    await page.locator('#new-value-row').getByRole('button', { name: 'Save new value' }).click();
    await expect(page.getByText('permission denied', { exact: true })).toBeVisible();
  });
});
