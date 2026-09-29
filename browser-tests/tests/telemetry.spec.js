const { test, expect } = require('@playwright/test');
const {
  signedIn,
  mockValues,
  mockApplication,
  mockDiscovery,
  openCallback
} = require('./helpers');

// The page's own origin: the ingest is same-origin with the app, and the
// server hands the page exactly that (README "Observability").
const endpoint = 'http://127.0.0.1:8088';
const telemetryConfig = 'globalThis.SOVEREIGN_CONFIG={issuer:"https://auth.example.test/application/o/sovereign-config/",clientId:"sovereign-config",telemetry:{endpoint:"http://127.0.0.1:8088",serviceVersion:"2.38.0-test"}};';
const VALUES = { '/apps/api/enabled': 'secret-looking-content' };

async function withTelemetry(page) {
  await page.route('**/app-config.js', route => route.fulfill({
    contentType: 'text/javascript',
    body: telemetryConfig
  }));
}

// Every `POST /v1/logs`, answered by `answer` (a status, or 'unreachable').
async function mockIngest(page, answer = 200) {
  const posts = [];
  await page.route(`${endpoint}/v1/logs`, route => {
    const request = route.request();
    posts.push({
      method: request.method(),
      authorization: request.headers().authorization,
      body: JSON.parse(request.postData())
    });
    if (answer === 'unreachable') return route.abort('connectionrefused');
    if (answer === 401) {
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: '{"code":16,"message":"missing scope: telemetry:write"}'
      });
    }
    return route.fulfill({ status: answer, contentType: 'application/json', body: '{"partialSuccess":{}}' });
  });
  return posts;
}

function consoleLines(page) {
  const lines = [];
  page.on('console', message => lines.push({ type: message.type(), text: message.text() }));
  return lines;
}

function records(post) {
  return post.body.resourceLogs.flatMap(resource =>
    resource.scopeLogs.flatMap(scope => scope.logRecords));
}

function attribute(record, key) {
  const found = record.attributes.find(entry => entry.key === key);
  return found && (found.value.stringValue ?? found.value.intValue);
}

// Opens a path in the grid: one user action, whose calls are ListValues.
async function openPath(page, path) {
  const listed = page.waitForResponse(response => response.url().endsWith('/ListValues'));
  await page.getByLabel('Selected path').fill(path);
  await page.getByRole('button', { name: 'Open', exact: true }).click();
  await listed;
}

// Waits until nothing new has been posted for `quiet` milliseconds.
async function settle(page, posts, quiet = 2500) {
  let seen = -1;
  while (seen !== posts.length) {
    seen = posts.length;
    await page.waitForTimeout(quiet);
  }
}

test.describe('client telemetry', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('a page action is one POST /v1/logs with a bearer, and its records carry the action\'s trace', async ({ page }) => {
    await withTelemetry(page);
    const posts = await mockIngest(page);
    const grpc = [];
    page.on('request', request => {
      if (request.url().includes('/sovereign.config.')) {
        grpc.push({ url: request.url(), traceparent: request.headers().traceparent });
      }
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await expect.poll(() => posts.length, { timeout: 15000 }).toBeGreaterThan(0);
    await settle(page, posts);

    posts.length = 0;
    grpc.length = 0;
    await openPath(page, '/apps/api');
    await expect(page.getByLabel('Value for enabled')).toHaveValue('secret-looking-content');
    await expect.poll(() => posts.length, { timeout: 15000 }).toBe(1);
    await settle(page, posts);
    expect(posts).toHaveLength(1);

    const [post] = posts;
    expect(post.method).toBe('POST');
    expect(post.authorization).toBe('Bearer access-token-two');
    const resource = post.body.resourceLogs[0].resource.attributes;
    expect(resource).toEqual([
      { key: 'service.name', value: { stringValue: 'sovereign-config-web' } },
      { key: 'service.version', value: { stringValue: '2.38.0-test' } }
    ]);

    // The gRPC-Web call carried a sampled W3C traceparent, and the record of
    // that call carries the same trace and the action's span.
    const listing = grpc.find(call => call.url.endsWith('/ListValues'));
    expect(listing.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    const [, traceId, spanId] = listing.traceparent.split('-');
    const record = records(post).find(entry => attribute(entry, 'rpc.method') === 'ListValues');
    expect(record.traceId).toBe(traceId);
    expect(record.spanId).toBe(spanId);

    // Nothing the page showed, nothing identifying, and no token in the body.
    const text = JSON.stringify(post.body);
    expect(text).not.toContain('secret-looking-content');
    expect(text).not.toContain('/apps/api');
    expect(text).not.toContain('access-token');
    for (const entry of records(post)) {
      for (const { key } of entry.attributes) {
        expect(key).not.toMatch(/token|password|secret|value|^user\./);
      }
    }
  });

  test('logging out discards what is waiting, so nothing leaves after the session', async ({ page }) => {
    await withTelemetry(page);
    const posts = await mockIngest(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await expect.poll(() => posts.length, { timeout: 15000 }).toBeGreaterThan(0);
    await settle(page, posts);

    // Records from this action wait out a one-second flush delay, which the
    // logout normally lands inside. On a loaded runner the batch may leave
    // first — that is before the session ended, and allowed — so what is
    // asserted is only what leaves afterwards.
    await openPath(page, '/apps/api');
    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
    const sentBeforeLogout = posts.length;
    await page.waitForTimeout(4000);
    expect(posts.length, 'nothing is sent once the session has ended').toBe(sentBeforeLogout);
  });

  test('a page with an ingest asks the provider for telemetry:write', async ({ page }) => {
    await withTelemetry(page);
    await mockDiscovery(page);
    const authorization = page.waitForRequest('https://auth.example.test/application/o/authorize/**');
    await page.route('https://auth.example.test/application/o/authorize/**', route => route.fulfill({
      contentType: 'text/html',
      body: '<h1>Identity provider</h1>'
    }));
    await page.goto('/');
    await page.getByRole('button', { name: 'Log in' }).click();
    const url = new URL((await authorization).url());
    expect(url.searchParams.get('scope'))
      .toBe('openid profile email sovereign-config offline_access telemetry:write');
  });

  test('with no telemetry configuration no request is made and the console says so once', async ({ page }) => {
    const lines = consoleLines(page);
    const posts = await mockIngest(page);
    const any = [];
    page.on('request', request => {
      if (new URL(request.url()).pathname.startsWith('/v1/')) any.push(request.url());
    });
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openPath(page, '/apps/api');
    await page.waitForTimeout(3000);
    expect(posts).toHaveLength(0);
    expect(any).toHaveLength(0);
    expect(lines.filter(line => line.text.includes('client telemetry is off'))).toHaveLength(1);
  });

  test('an ingest answering 401 leaves the UI unchanged and says so once', async ({ page }) => {
    await withTelemetry(page);
    const lines = consoleLines(page);
    const posts = await mockIngest(page, 401);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openPath(page, '/apps/api');
    await expect.poll(() => posts.length, { timeout: 15000 }).toBeGreaterThan(0);
    // The refused token is marked stale; the page's next call refreshes it,
    // the next export is refused again, and export stops for the page.
    await openPath(page, '/apps');
    await openPath(page, '/apps/api');
    await expect.poll(
      () => lines.filter(line => line.type === 'warning' && line.text.includes('client telemetry')).length,
      { timeout: 20000 }
    ).toBe(1);
    const stoppedAt = posts.length;
    await openPath(page, '/apps');
    await openPath(page, '/apps/api');
    await page.waitForTimeout(3000);
    expect(posts.length, 'nothing more is sent once export has stopped').toBe(stoppedAt);
    const warnings = lines.filter(line => line.type === 'warning' && line.text.includes('client telemetry'));
    expect(warnings).toHaveLength(1);
    expect(warnings[0].text).toContain('HTTP 401');
    await expect(signedIn(page)).toBeVisible();
    await expect(page.locator('#error')).toBeHidden();
  });

  test('an unreachable ingest leaves the UI unchanged and warns once', async ({ page }) => {
    await withTelemetry(page);
    const lines = consoleLines(page);
    const posts = await mockIngest(page, 'unreachable');
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openPath(page, '/apps/api');
    await expect.poll(() => posts.length, { timeout: 15000 }).toBeGreaterThan(0);
    await openPath(page, '/apps');
    await openPath(page, '/apps/api');
    await page.waitForTimeout(3000);
    // One line when it starts failing, and never one per batch: the most
    // there can be is that line and, much later, the one giving up.
    const warnings = lines.filter(line => line.type === 'warning' && line.text.includes('client telemetry'));
    expect(warnings.filter(line => line.text.includes('is failing (unreachable)'))).toHaveLength(1);
    expect(warnings.length).toBeLessThanOrEqual(2);
    await expect(signedIn(page)).toBeVisible();
    await expect(page.locator('#error')).toBeHidden();
  });
});
