const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const {
  signedIn,
  openView,
  mockValues,
  mockApplication,
  negotiate,
  mockAudit,
  openCallback
} = require('./helpers');

// Timestamps are drawn and datetime filters are read in the browser's zone;
// pinning it makes both exact.
test.use({ timezoneId: 'UTC' });

// 2023-11-14 22:13:20 UTC.
const T = 1700000000;

// Newest first, as the service returns them.
const EVENTS = [
  { id: 1, kind: 'value.updated', path: '/apps/api/token', at: T, name: 'A Vincent', narrative: 'A Vincent changed /apps/api/token' },
  { id: 2, kind: 'secret.revealed', path: '/apps/api/password', at: T - 100, firstAt: T - 3600, count: 14, subject: 'provider-subject', protocol: 'v3', narrative: 'provider-subject revealed /apps/api/password 14 times between 21:13 and 22:11' },
  { id: 3, kind: 'subtree.read', path: '/apps', at: T - 200, name: 'A Vincent', narrative: 'A Vincent read /apps' },
  { id: 4, kind: 'values.listed', path: '/apps/api', at: T - 300, name: 'A Vincent', narrative: 'A Vincent listed /apps/api' },
  { id: 7, kind: 'subtree.read', path: '/other', at: T - 400, name: 'A Vincent', narrative: 'A Vincent read /other' },
  { id: 5, kind: 'value.created', path: '/apps/worker/concurrency', at: T - 86400, name: 'A Vincent', narrative: 'A Vincent created /apps/worker/concurrency' },
  { id: 6, kind: 'connection.created', path: '/apps/api', at: T - 90000, name: 'A Vincent', narrative: 'A Vincent created the access URL Pipeline reader for /apps/api' }
];

// Enough rows that the first page runs well past the viewport and its
// prefetch margin, so a further page is only fetched by scrolling.
const MANY = Array.from({ length: 60 }, (_, index) => ({
  id: 1000 - index,
  kind: 'value.updated',
  path: `/apps/bulk/value-${index}`,
  at: T - index * 60,
  name: 'A Vincent',
  narrative: `A Vincent changed /apps/bulk/value-${index}`
}));

function rows(page) {
  return page.locator('#audit-body tr');
}

function narratives(page) {
  return page.locator('#audit-body .audit-narrative');
}

// A v4 session: the audit trail is not served on v3.
async function signIn(page, events, options = {}) {
  await negotiate(page, 'v4');
  const audit = await mockAudit(page, { events, ...options });
  await openCallback(page);
  await expect(signedIn(page)).toBeVisible();
  return audit;
}

async function scrollToEnd(page) {
  await page.locator('#audit-sentinel').scrollIntoViewIfNeeded();
}

test.describe('audit trail', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('opens from the brand menu on changes and reveals, with reads one click away', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    await openView(page, 'Audit trail');
    await expect(page).toHaveURL(/\/audit\/$/);
    await expect(page.getByRole('heading', { name: 'Audit trail', level: 1 })).toBeVisible();

    await expect(narratives(page)).toHaveText([
      'A Vincent changed /apps/api/token',
      'provider-subject revealed /apps/api/password 14 times between 21:13 and 22:11',
      'A Vincent created /apps/worker/concurrency',
      'A Vincent created the access URL Pipeline reader for /apps/api'
    ]);
    expect(audit.requests).toHaveLength(1);
    expect(audit.requests[0].kinds).not.toContain('subtree.read');
    expect(audit.requests[0].kinds).not.toContain('values.listed');
    expect(audit.requests[0].kinds).toContain('secret.revealed');
    await expect(page.locator('#audit-state')).toHaveText('4 events');

    // Timestamp, actor, narrative and protocol version, in that order. The
    // coalesced row is dated by its first occurrence and its narrative
    // carries the count and period.
    await expect(rows(page).nth(0).locator('td')).toHaveText([
      '14/11/2023, 22:13:20',
      'A Vincent',
      /A Vincent changed \/apps\/api\/token/,
      'v4'
    ]);
    await expect(rows(page).nth(1).locator('td')).toHaveText([
      '14/11/2023, 21:13:20',
      'provider-subject',
      /14 times between 21:13 and 22:11/,
      'v3'
    ]);

    await page.getByLabel('Reads').check();
    await expect(rows(page)).toHaveCount(7);
    expect(audit.requests.at(-1).kinds).toEqual([]);

    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations).toEqual([]);
  });

  test('is reachable by URL', async ({ page }) => {
    await signIn(page, EVENTS);
    await page.goto('/audit/');
    await expect(page.getByRole('heading', { name: 'Audit trail', level: 1 })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Audit trail', exact: true, includeHidden: true }))
      .toHaveAttribute('aria-current', 'page');
    await expect(narratives(page).first()).toHaveText('A Vincent changed /apps/api/token');
  });

  test('filters by path, description, time range, protocol version and event kind', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    await page.goto('/audit/');
    await expect(rows(page)).toHaveCount(4);

    await page.getByLabel('Path contains').fill('WORKER');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(narratives(page)).toHaveText(['A Vincent created /apps/worker/concurrency']);
    expect(audit.requests.at(-1).pathFilter).toBe('WORKER');
    await page.getByLabel('Path contains').fill('');

    await page.getByLabel('Description contains').fill('revealed');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(narratives(page)).toHaveText([/revealed \/apps\/api\/password/]);
    expect(audit.requests.at(-1)).toMatchObject({ pathFilter: '', textFilter: 'revealed' });
    await page.getByLabel('Description contains').fill('');

    await page.getByLabel('Protocol version').fill('v3');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(narratives(page)).toHaveText([/revealed \/apps\/api\/password/]);
    expect(audit.requests.at(-1)).toMatchObject({ textFilter: '', protocolVersion: 'v3' });
    await page.getByLabel('Protocol version').fill('');

    await page.getByLabel('From').fill('2023-11-14T00:00');
    await page.getByLabel('Until').fill('2023-11-14T23:59');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(narratives(page)).toHaveText([
      'A Vincent changed /apps/api/token',
      /revealed \/apps\/api\/password/
    ]);
    expect(audit.requests.at(-1)).toMatchObject({
      protocolVersion: '',
      from: 1699920000,
      // Through the end of the minute picked, not its first instant.
      until: 1700006399
    });
    await page.getByLabel('From').fill('');
    await page.getByLabel('Until').fill('');

    await page.getByLabel('Changes', { exact: true }).uncheck();
    await page.getByLabel('Access URL changes').uncheck();
    await expect(narratives(page)).toHaveText([/revealed \/apps\/api\/password/]);
    expect(audit.requests.at(-1).kinds).toEqual(['secret.revealed']);
  });

  test('refuses filters the service would reject, without asking it', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    await page.goto('/audit/');
    await expect(rows(page)).toHaveCount(4);
    const asked = audit.requests.length;

    await page.getByLabel('Path contains').fill('apps.api');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(page.locator('#audit-path-filter-error')).toBeVisible();
    await expect(page.getByLabel('Path contains')).toHaveAttribute('aria-invalid', 'true');

    expect(audit.requests).toHaveLength(asked);

    // Correcting the field clears its error as it is typed, before anything
    // else is clicked.
    await page.getByLabel('Path contains').fill('');
    await expect(page.locator('#audit-path-filter-error')).toBeHidden();

    await page.getByLabel('Changes', { exact: true }).uncheck();
    await page.getByLabel('Secret reveals').uncheck();
    await expect(narratives(page)).toHaveText([/access URL Pipeline reader/]);
    const beforeLast = audit.requests.length;
    await page.getByLabel('Access URL changes').uncheck();
    await expect(page.locator('#audit-kinds-error')).toHaveText('choose at least one kind of event');
    expect(audit.requests).toHaveLength(beforeLast);
  });

  test('an applied filter the service would refuse clears the list rather than paging the old one', async ({ page }) => {
    const audit = await signIn(page, MANY, { pageSize: 25 });
    await page.goto('/audit/');
    await expect(rows(page)).toHaveCount(25);
    const asked = audit.requests.length;

    await page.getByLabel('Protocol version').fill('V4');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(page.locator('#audit-protocol-error')).toBeVisible();
    await expect(rows(page)).toHaveCount(0);
    await expect(page.locator('#audit-state')).toHaveText('Check the filters');

    await scrollToEnd(page);
    await page.waitForTimeout(300);
    expect(audit.requests).toHaveLength(asked);
    await expect(page.locator('#audit-state')).toHaveText('Check the filters');

    // Correcting it asks afresh, from the first page.
    await page.getByLabel('Protocol version').fill('v4');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(rows(page)).toHaveCount(25);
    expect(audit.requests.at(-1)).toMatchObject({ protocolVersion: 'v4', cursor: '' });
  });

  test('loads further pages as it scrolls, once each, and stops at the end', async ({ page }) => {
    const audit = await signIn(page, MANY, { pageSize: 25 });
    await page.goto('/audit/');
    await expect(rows(page)).toHaveCount(25);
    await expect(page.locator('#audit-state')).toHaveText('25 events so far');
    expect(audit.requests.map(request => request.cursor)).toEqual(['']);

    await scrollToEnd(page);
    await expect(rows(page)).toHaveCount(50);
    await scrollToEnd(page);
    await expect(rows(page)).toHaveCount(60);
    await expect(page.locator('#audit-state')).toHaveText('60 events');

    // Scrolling on past the end asks for nothing more.
    await page.mouse.wheel(0, -2000);
    await scrollToEnd(page);
    await page.waitForTimeout(300);
    expect(audit.requests.map(request => request.cursor)).toEqual(['', '25', '50']);
    await expect(narratives(page).last()).toHaveText('A Vincent changed /apps/bulk/value-59');
  });

  test('a failed page reports the error, keeps its rows and can be retried', async ({ page }) => {
    const audit = await signIn(page, MANY, { pageSize: 25 });
    await page.goto('/audit/');
    await expect(rows(page)).toHaveCount(25);

    audit.failNext();
    await scrollToEnd(page);
    await expect(page.locator('#audit-page-error')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
    await expect(rows(page)).toHaveCount(25);
    const failed = audit.requests.length;

    // The list is not wedged, but neither does scrolling hammer a failing
    // service: only the retry asks again.
    await page.mouse.wheel(0, -2000);
    await scrollToEnd(page);
    await page.waitForTimeout(300);
    expect(audit.requests).toHaveLength(failed);

    await page.getByRole('button', { name: 'Retry' }).click();
    await expect(rows(page)).toHaveCount(50);
    await expect(page.locator('#audit-page-error')).toBeHidden();
    expect(audit.requests.map(request => request.cursor)).toEqual(['', '25', '25']);

    // Retrying re-arms the scroll.
    await scrollToEnd(page);
    await expect(rows(page)).toHaveCount(60);
  });

  test('a failed first page can be retried', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    audit.failNext();
    await page.goto('/audit/');
    await expect(page.locator('#audit-page-error')).toBeVisible();
    await expect(rows(page)).toHaveCount(0);
    await page.getByRole('button', { name: 'Retry' }).click();
    await expect(rows(page)).toHaveCount(4);
  });

  test('a page that arrives for a superseded filter is discarded', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    const releaseFirst = audit.delayNext();
    await page.goto('/audit/');
    await expect.poll(() => audit.requests.length).toBe(1);

    await page.getByLabel('Description contains').fill('worker');
    await page.getByRole('button', { name: 'Filter' }).click();
    await expect(narratives(page)).toHaveText(['A Vincent created /apps/worker/concurrency']);

    releaseFirst();
    await page.waitForTimeout(300);
    await expect(narratives(page)).toHaveText(['A Vincent created /apps/worker/concurrency']);
    await expect(page.locator('#audit-state')).toHaveText('1 event');
  });

  test('each value opens its own history, including the reads that reached it', async ({ page }) => {
    const audit = await signIn(page, EVENTS, { pageSize: 25 });
    await mockValues(page, { '/apps/api/token': 'secret-free', '/apps/api/other': 'x' });
    await page.goto('/configuration/apps/api');
    await expect(page.getByRole('row', { name: /token/ })).toBeVisible();

    await page.getByRole('button', { name: 'Show the audit trail for token' }).click();
    await expect(page).toHaveURL(/\/audit\/apps\/api\/token$/);
    await expect(page.locator('#audit-element-path')).toHaveText('/apps/api/token');
    await expect(page.getByLabel('Path contains')).toBeDisabled();
    await expect(page.getByLabel('Reads')).toBeChecked();
    await expect(narratives(page)).toHaveText([
      'A Vincent changed /apps/api/token',
      'A Vincent read /apps',
      'A Vincent listed /apps/api'
    ]);
    expect(audit.requests.at(-1)).toMatchObject({ elementPath: '/apps/api/token', pathFilter: '', kinds: [] });

    await page.getByRole('link', { name: 'Show the whole trail' }).click();
    await expect(page).toHaveURL(/\/audit\/$/);
    await expect(page.getByLabel('Path contains')).toBeEnabled();
    await expect(page.getByLabel('Reads')).not.toBeChecked();
    await expect(rows(page)).toHaveCount(4);
    expect(audit.requests.at(-1).elementPath).toBe('');
  });

  test('the history button waits for a decision about an unsaved edit', async ({ page }) => {
    const audit = await signIn(page, EVENTS);
    await mockValues(page, { '/apps/api/token': 'before' });
    await page.goto('/configuration/apps/api');
    await page.getByLabel('Value for token').fill('after');

    await page.getByRole('button', { name: 'Show the audit trail for token' }).click();
    const dialog = page.getByRole('dialog', { name: 'Discard unsaved changes?' });
    await expect(dialog).toBeVisible();
    await page.getByRole('button', { name: 'Keep editing' }).click();
    await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
    await expect(page.getByLabel('Value for token')).toHaveValue('after');
    expect(audit.requests).toHaveLength(0);

    await page.getByRole('button', { name: 'Show the audit trail for token' }).click();
    await page.getByRole('button', { name: 'Discard changes' }).click();
    await expect(page).toHaveURL(/\/audit\/apps\/api\/token$/);
    await expect(rows(page)).toHaveCount(3);
  });
});
