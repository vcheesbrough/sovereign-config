const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  grpcFrame,
  mockValues,
  mockApplication,
  mockConnections,
  openCallback,
  TREE_VALUES,
  treeNode,
  openConfiguration
} = require('./helpers');

test.describe('tree', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('the sidebar tree draws unbroken ancestry guides', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await expect(treeNode(page, '/apps/api/nested')).toHaveCount(1);

    // One guide cell per level of depth, each classed by the rule it draws.
    const classes = await page.evaluate(() => Object.fromEntries(
      ['/', '/apps', '/apps/api', '/apps/api/nested', '/apps/worker'].map(path => [
        path,
        [...document.querySelectorAll(`#config-tree [data-path="${path}"] .tree-guide`)]
          .map(guide => guide.className)
      ])
    ));
    expect(classes).toEqual({
      '/': [],
      '/apps': ['tree-guide corner'],
      '/apps/api': ['tree-guide', 'tree-guide branch'],
      '/apps/api/nested': ['tree-guide', 'tree-guide trunk', 'tree-guide corner'],
      '/apps/worker': ['tree-guide', 'tree-guide corner']
    });

    // The regression this guards: box-drawing glyphs only paint inside their own
    // line box, so a trunk assembled from them broke at every row boundary. The
    // rules are pinned to the full height of their cell, so a trunk continuing
    // from one row into the next must leave no gap at all between the two.
    const [above, below] = await page.evaluate(() => ['/apps/api', '/apps/api/nested']
      .map(path => document
        .querySelectorAll(`#config-tree [data-path="${path}"] .tree-guide`)[1]
        .getBoundingClientRect())
      .map(({ top, bottom, left, height }) => ({ top, bottom, left, height })));
    expect(below.top).toBeCloseTo(above.bottom, 1);
    expect(below.left).toBeCloseTo(above.left, 1);
    expect(above.height).toBeGreaterThan(0);
  });

  test('the sidebar tree lists every namespace and selects one on a single click', async ({ page }) => {
    await mockConnections(page, {
      connections: [{ name: 'Pipeline reader', root: '/apps/api', permissions: [1] }]
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);

    const tree = page.getByRole('tree', { name: 'Configuration tree' });
    await expect(tree.getByRole('treeitem')).toHaveCount(5);
    for (const path of ['/', '/apps', '/apps/api', '/apps/api/nested', '/apps/worker']) {
      await expect(treeNode(page, path)).toHaveCount(1);
    }
    // `/apps` is only an ancestor: it holds no value of its own and is not bold.
    await expect(treeNode(page, '/apps')).not.toHaveClass(/has-values/);
    await expect(treeNode(page, '/apps/api')).toHaveClass(/has-values/);
    await expect(treeNode(page, '/')).toHaveClass(/has-values/);
    const weights = await page.evaluate(() => ['/apps', '/apps/api'].map(path => (
      getComputedStyle(document.querySelector(`#config-tree [data-path="${path}"]`)).fontWeight
    )));
    expect(Number(weights[1])).toBeGreaterThan(Number(weights[0]));

    // Only the access URL's own root is keyed, and the key carries a name.
    await expect(page.locator('#config-tree .tree-key')).toHaveCount(1);
    await expect(treeNode(page, '/apps/api')).toHaveAccessibleName(/access URL/);

    // Parents are marked expanded; leaves carry no expansion state at all.
    await expect(treeNode(page, '/apps')).toHaveAttribute('aria-expanded', 'true');
    await expect(treeNode(page, '/apps/api')).toHaveAttribute('aria-expanded', 'true');
    expect(await treeNode(page, '/apps/worker').evaluate(node => node.hasAttribute('aria-expanded')))
      .toBe(false);

    // Nothing deeper is selected, so the root node holds the selection.
    await expect(treeNode(page, '/')).toHaveAttribute('aria-selected', 'true');

    await treeNode(page, '/apps/worker').click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
    await expect(page.getByRole('row', { name: /concurrency/ })).toBeVisible();
    await expect(treeNode(page, '/apps/worker')).toHaveAttribute('aria-selected', 'true');
    await expect(treeNode(page, '/')).toHaveAttribute('aria-selected', 'false');
    await expect(page.getByLabel('Selected path')).toHaveValue('/apps/worker');

    // The tree is one tab stop and moves with the arrow keys.
    await treeNode(page, '/apps/worker').press('ArrowUp');
    await expect(treeNode(page, '/apps/api/nested')).toBeFocused();

    // Neither boundary wraps, per the WAI-ARIA tree pattern.
    await treeNode(page, '/apps/api/nested').press('Home');
    await expect(treeNode(page, '/')).toBeFocused();
    await treeNode(page, '/').press('ArrowUp');
    await expect(treeNode(page, '/')).toBeFocused();
    await treeNode(page, '/').press('End');
    await expect(treeNode(page, '/apps/worker')).toBeFocused();
    await treeNode(page, '/apps/worker').press('ArrowDown');
    await expect(treeNode(page, '/apps/worker')).toBeFocused();

    // Activating rebuilds the tree; focus must land on the node just selected
    // rather than being dropped onto the document.
    await treeNode(page, '/apps/worker').press('ArrowUp');
    await treeNode(page, '/apps/api/nested').press('Enter');
    await expect(page).toHaveURL(/\/configuration\/apps\/api\/nested$/);
    await expect(treeNode(page, '/apps/api/nested')).toBeFocused();
    // Still true once the asynchronous reload has replaced the nodes again.
    await expect.poll(async () => page.evaluate(() => document.activeElement.dataset.path))
      .toBe('/apps/api/nested');

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });

  test('the tree renders a namespace label in the case of its fold-smallest contributing path', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    // "/Zone/alpha/one" and "/zone/beta/two" disagree on "/zone"'s case.
    // "alpha" sorts before "beta" as a fold key, so "/Zone/alpha/one" is the
    // fold-smallest path sharing that ancestor and its case wins the label —
    // deterministic, and independent of write order (card #294).
    await mockValues(page, {
      '/Zone/alpha/one': '1',
      '/zone/beta/two': '2'
    });
    await openConfiguration(page);

    const tree = page.getByRole('tree', { name: 'Configuration tree' });
    await expect(tree.getByRole('treeitem')).toHaveCount(4);
    await expect(treeNode(page, '/zone').locator('.tree-label')).toHaveText('Zone');
    await expect(treeNode(page, '/zone/alpha').locator('.tree-label')).toHaveText('alpha');
    await expect(treeNode(page, '/zone/beta').locator('.tree-label')).toHaveText('beta');

    await treeNode(page, '/zone/alpha').click();
    await expect(page.getByRole('row', { name: /one/ })).toBeVisible();
  });

  test('the grid shows a value under the case it was written with', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, { '/apps/api/serverIP': '10.0.0.1' });
    await page.goto('/configuration/apps/api');
    await expect(page.getByRole('row', { name: /serverIP/ })).toBeVisible();
    await expect(page.locator('.value-name')).toHaveText('serverIP');
    await expect(page.locator('.full-path')).toHaveText('/apps/api/serverIP');
  });

  test('the tree gains a node for a new namespace and loses an emptied one', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, { '/apps/api/enabled': 'true' });
    await openConfiguration(page);
    await expect(treeNode(page, '/apps/worker')).toHaveCount(0);

    await page.getByLabel('Selected path').fill('/apps/worker');
    await page.getByRole('button', { name: 'Open' }).click();
    await page.getByRole('button', { name: 'Add value' }).click();
    await page.getByPlaceholder('value-name').fill('concurrency');
    await page.getByLabel('Value', { exact: true }).fill('4');
    await page.locator('#new-value-row').getByRole('button', { name: 'Save new value' }).click();
    await expect(treeNode(page, '/apps/worker')).toHaveCount(1);

    await page.getByRole('button', { name: 'Delete concurrency' }).click();
    await page.locator('#confirm-delete').click();
    await expect(treeNode(page, '/apps/worker')).toHaveCount(0);
    await expect(treeNode(page, '/apps/api')).toHaveCount(1);
  });

  test('leaving a path with an unsaved value is guarded by a confirmation', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();
    const editor = page.getByLabel('Value for enabled');
    await editor.fill('edited-but-unsaved');

    await treeNode(page, '/apps/worker').click();
    const dialog = page.locator('#unsaved-dialog');
    await expect(dialog).toBeVisible();
    await page.locator('#keep-editing').click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
    await expect(editor).toHaveValue('edited-but-unsaved');

    // The browser Back button cannot be cancelled, so the guard restores the URL.
    await page.goBack();
    await expect(dialog).toBeVisible();
    await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
    await page.locator('#keep-editing').click();
    await expect(editor).toHaveValue('edited-but-unsaved');

    // Restoring the stored text makes the row clean again, so navigation is free.
    await editor.fill('true');
    await treeNode(page, '/apps/worker').click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);

    // Discarding after a Back press must not leave a duplicate entry behind, or
    // the next Back would return to the page just left instead of going further.
    await treeNode(page, '/apps/api').click();
    await page.getByLabel('Value for enabled').fill('edited-again');
    await page.goBack();
    await expect(dialog).toBeVisible();
    await page.locator('#discard-changes').click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
    await page.goBack();
    await expect(page).not.toHaveURL(/\/configuration\/apps\/api$/);

    // Back on the edited path for the nav-link case below.
    await treeNode(page, '/apps/api').click();
    await page.getByLabel('Value for enabled').fill('edited-but-unsaved');

    // A menu link out of the view is guarded on the same terms.
    await openView(page, 'Downloads');
    await expect(dialog).toBeVisible();
    await page.locator('#discard-changes').click();
    await expect(page).toHaveURL(/\/downloads$/);

    // The discarded edit is gone; the stored value is what comes back.
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();
    await expect(page.getByLabel('Value for enabled')).toHaveValue('true');
    await treeNode(page, '/apps/worker').click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
  });

  test('a value with CRLF line endings is not mistaken for an unsaved edit', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, {
      '/apps/api/script': 'line-one\r\nline-two',
      '/apps/worker/concurrency': '4'
    });
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();

    // A textarea normalizes CRLF to LF, so the loaded marker has to come from the
    // control rather than from the stored string it was assigned.
    const editor = page.getByLabel('Value for script');
    await expect(editor).toHaveValue('line-one\nline-two');
    expect(await editor.evaluate(field => field.value === field.getAttribute('data-loaded'))).toBe(true);

    // Nothing was edited, so leaving must not ask.
    await treeNode(page, '/apps/worker').click();
    await expect(page.locator('#unsaved-dialog')).toBeHidden();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
  });

  test('escaping the guard keeps the edit and abandons the route it was holding', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();
    const editor = page.getByLabel('Value for enabled');
    await editor.fill('edited-but-unsaved');

    // Escape is neither button, so it must read as a decision to stay.
    await treeNode(page, '/apps/api/nested').click();
    const dialog = page.locator('#unsaved-dialog');
    await expect(dialog).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
    await expect(editor).toHaveValue('edited-but-unsaved');

    // The abandoned route must not survive: discarding later has to go where the
    // operator asked then, not where they declined to go before.
    await treeNode(page, '/apps/worker').click();
    await expect(dialog).toBeVisible();
    await page.locator('#discard-changes').click();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
  });

  test('a full-page exit is guarded only while an edit is unsaved', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();

    // The browser's own prompt is not scriptable, so assert on the signal the
    // handler produces: a cancelled beforeunload event.
    const cancelled = () => page.evaluate(() => {
      const event = new Event('beforeunload', { cancelable: true });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    });
    expect(await cancelled()).toBe(false);

    await page.getByLabel('Value for enabled').fill('edited-but-unsaved');
    expect(await cancelled()).toBe(true);

    await page.getByLabel('Value for enabled').fill('true');
    expect(await cancelled()).toBe(false);
  });

  test('a saved edit leaves nothing to guard', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await treeNode(page, '/apps/api').click();
    await page.getByLabel('Value for enabled').fill('false');
    await page.getByRole('button', { name: 'Save enabled' }).click();
    await expect(page.getByText('Saved', { exact: true })).toBeVisible();

    await treeNode(page, '/apps/worker').click();
    await expect(page.locator('#unsaved-dialog')).toBeHidden();
    await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
  });

  test('the sidebar is drag resizable and keeps its width across a reload', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);

    const sidebar = page.locator('#sidebar');
    const initial = (await sidebar.boundingBox()).width;
    // Wider than the fixed 224px the sidebar used before the tree moved in.
    expect(initial).toBeGreaterThan(224);

    const handle = await page.locator('#sidebar-resizer').boundingBox();
    await page.mouse.move(handle.x + handle.width / 2, handle.y + 100);
    await page.mouse.down();
    await page.mouse.move(initial + 120, handle.y + 100, { steps: 10 });
    await page.mouse.up();
    const dragged = (await sidebar.boundingBox()).width;
    expect(dragged).toBeGreaterThan(initial + 80);

    // The separator is operable from the keyboard too.
    await page.locator('#sidebar-resizer').focus();
    await page.keyboard.press('ArrowLeft');
    expect((await sidebar.boundingBox()).width).toBeCloseTo(dragged - 16, 0);

    await page.reload();
    await expect.poll(async () => (await page.locator('#sidebar').boundingBox()).width)
      .toBeGreaterThan(initial + 60);
  });

  test('a tall sidebar scrolls as a whole rather than lengthening the page', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, Object.fromEntries(
      Array.from({ length: 60 }, (_, index) => [`/services/service-${index + 1}/enabled`, 'true'])
    ));
    await openConfiguration(page);
    await expect(page.getByRole('tree').getByRole('treeitem')).toHaveCount(62);

    const viewport = page.viewportSize().height;
    const sidebar = await page.locator('#sidebar').boundingBox();
    // The sidebar claims the viewport below the header and no more, however many
    // nodes the tree holds.
    expect(sidebar.y).toBeCloseTo(48, 0);
    expect(sidebar.y + sidebar.height).toBeLessThanOrEqual(viewport + 1);

    // The sidebar scrolls as a whole, so the tree's status line travels with the
    // nodes rather than staying pinned above them.
    const scroller = page.locator('#sidebar-scroll');
    expect(await scroller.evaluate(box => box.scrollHeight > box.clientHeight)).toBe(true);
    expect(await page.locator('#config-tree').evaluate(list => list.scrollHeight <= list.clientHeight))
      .toBe(true);

    const stateBefore = (await page.locator('#config-tree-state').boundingBox()).y;
    await scroller.evaluate(box => { box.scrollTop = 300; });
    expect(await scroller.evaluate(box => box.scrollTop)).toBeGreaterThan(0);
    const stateAfter = (await page.locator('#config-tree-state').boundingBox()).y;
    expect(stateBefore - stateAfter).toBeGreaterThan(200);

    // Scrolling the sidebar moves the sidebar, not the document.
    expect(await page.evaluate(() => window.scrollY)).toBe(0);

    // The page's height is driven by the main column, never by the sidebar: laid
    // out in full, 60-odd nodes are far taller than the document ever becomes.
    const heights = await page.evaluate(() => ({
      document: document.documentElement.scrollHeight,
      sidebar: document.getElementById('sidebar-scroll').scrollHeight
    }));
    expect(heights.sidebar).toBeGreaterThan(heights.document);

    // With enough main content to scroll, the sidebar stays pinned in view.
    await page.locator('#config-tree [data-path="/services/service-1"]').click();
    await page.evaluate(() => window.scrollTo(0, 400));
    const scrolled = await page.locator('#sidebar').boundingBox();
    expect(scrolled.y).toBeGreaterThanOrEqual(0);
    expect(scrolled.y).toBeLessThanOrEqual(64);
  });

  test('the tree still renders when the estate cannot be read whole', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    // A principal scoped to a prefix is refused the root subtree; the namespace
    // list ListValues returns still carries the shape of the tree.
    await page.route('**/sovereign.config.v3.Configuration/GetSubTree', route => route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(Buffer.alloc(0), 7)
    }));
    await openConfiguration(page);

    await expect(treeNode(page, '/apps/api')).toHaveCount(1);
    await expect(treeNode(page, '/apps/worker')).toHaveCount(1);
    // Without the whole estate the value marker cannot be known, so none is shown.
    await expect(page.locator('#config-tree .has-values')).toHaveCount(0);
  });

  test('logging out empties the sidebar tree', async ({ page }) => {
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, TREE_VALUES);
    await openConfiguration(page);
    await expect(page.getByRole('tree').getByRole('treeitem')).toHaveCount(5);

    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(page.getByRole('tree').getByRole('treeitem')).toHaveCount(0);
    await expect(page.locator('#config-tree-state')).toHaveText('Log in to browse');
  });
});
