const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const path = require('node:path');
const transportContract = require('../../test-contracts/transport.json');

const configScript = 'globalThis.SOVEREIGN_CONFIG={issuer:"https://auth.example.test/application/o/sovereign-config/",clientId:"sovereign-config"};';
const staticDir = process.env.PLAYWRIGHT_STATIC_DIR
  ? path.resolve(process.env.PLAYWRIGHT_STATIC_DIR)
  : path.resolve(__dirname, '../../web-dist');
const tokenEndpoint = 'https://auth.example.test/application/o/token/';

async function storedRefreshState(page) {
  return page.evaluate(() => ({
    token: sessionStorage.getItem('sovereign-config.refresh-token'),
    endpoint: sessionStorage.getItem('sovereign-config.refresh-endpoint'),
    expiry: sessionStorage.getItem('sovereign-config.refresh-expires-at')
  }));
}

function grpcFrame(payload, status = 0) {
  const dataHeader = Buffer.alloc(5);
  dataHeader.writeUInt32BE(payload.length, 1);
  const trailer = Buffer.from(`grpc-status: ${status}\r\n`);
  const trailerHeader = Buffer.alloc(5);
  trailerHeader[0] = 0x80;
  trailerHeader.writeUInt32BE(trailer.length, 1);
  return Buffer.concat([dataHeader, payload, trailerHeader, trailer]);
}

function varint(value) {
  const bytes = [];
  let current = BigInt(value);
  while (current >= 0x80n) {
    bytes.push(Number((current & 0x7fn) | 0x80n));
    current >>= 7n;
  }
  bytes.push(Number(current));
  return Buffer.from(bytes);
}

function field(number, payload) {
  return Buffer.concat([Buffer.from([(number << 3) | 2]), varint(payload.length), payload]);
}

function timestamp(seconds) {
  return Buffer.concat([Buffer.from([0x08]), varint(seconds)]);
}

function mutationReply() {
  const instant = timestamp(1700000000);
  return Buffer.concat([field(1, instant), field(2, instant)]);
}

function scalarField(number, value) {
  return Buffer.concat([varint(number << 3), varint(value)]);
}

function storedValue(value) {
  return typeof value === 'string' ? { value, secret: false } : value;
}

function subTreeValue(path, stored) {
  const value = storedValue(stored);
  return Buffer.concat([
    field(1, Buffer.from(path)),
    value.secret ? field(3, Buffer.alloc(0)) : field(2, Buffer.from(value.value)),
    scalarField(4, value.secret ? 2 : 1)
  ]);
}

function subtreeReply(values) {
  return Buffer.concat(values.map(([path, value]) => field(1, subTreeValue(path, value))));
}

function listedValue(path, stored) {
  const value = storedValue(stored);
  const instant = timestamp(1700000000);
  return Buffer.concat([
    field(1, Buffer.from(path)),
    value.secret ? field(5, Buffer.alloc(0)) : field(2, Buffer.from(value.value)),
    field(3, instant),
    field(4, instant),
    scalarField(6, value.secret ? 2 : 1)
  ]);
}

function listReply(values, paths) {
  return Buffer.concat([
    ...values.map(([path, value]) => field(1, listedValue(path, value))),
    ...paths.map(path => field(2, Buffer.from(path)))
  ]);
}

function readVarint(buffer, start) {
  let value = 0;
  let shift = 0;
  let offset = start;
  while (offset < buffer.length) {
    const byte = buffer[offset++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value, offset];
    shift += 7;
  }
  throw new Error('invalid protobuf varint');
}

function messageFields(buffer, start = 0) {
  const fields = new Map();
  let offset = start;
  while (offset < buffer.length) {
    const [tag, afterTag] = readVarint(buffer, offset);
    offset = afterTag;
    const number = tag >> 3;
    const wire = tag & 0x07;
    let value;
    if (wire === 2) {
      const [length, afterLength] = readVarint(buffer, offset);
      offset = afterLength;
      value = buffer.subarray(offset, offset + length);
      offset += length;
    } else if (wire === 0) {
      [value, offset] = readVarint(buffer, offset);
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
    const values = fields.get(number) || [];
    values.push(value);
    fields.set(number, values);
  }
  return fields;
}

function stringFields(frame) {
  const decoded = messageFields(frame, 5);
  const fields = new Map();
  for (const [number, values] of decoded) {
    const value = values[0];
    fields.set(number, Buffer.isBuffer(value) ? value.toString() : value);
  }
  return fields;
}

function nestedStringFields(message) {
  const decoded = messageFields(message);
  const fields = new Map();
  for (const [number, values] of decoded) {
    const value = values[0];
    fields.set(number, Buffer.isBuffer(value) ? value.toString() : value);
  }
  return fields;
}

function repeatedMessages(frame, number) {
  return (messageFields(frame, 5).get(number) || []).map(nestedStringFields);
}

function parentPath(path) {
  const split = path.lastIndexOf('/');
  return split <= 0 ? '/' : path.slice(0, split);
}

function existingPaths(values) {
  const paths = new Set();
  for (const path of values.keys()) {
    const parent = parentPath(path);
    if (parent === '/') {
      paths.add('/');
      continue;
    }
    const segments = parent.slice(1).split('/');
    for (let index = 1; index <= segments.length; index++) {
      paths.add(`/${segments.slice(0, index).join('/')}`);
    }
  }
  return [...paths].sort();
}

async function mockValues(page, initial = {}) {
  const stored = new Map(Object.entries(initial).map(([path, value]) => [path, storedValue(value)]));
  const requests = [];
  let delayedSubtree;
  await page.route('**/sovereign.config.v3.Configuration/*', async route => {
    const method = route.request().url().split('/').pop();
    const body = route.request().postDataBuffer();
    const fields = stringFields(body);
    requests.push({ method, body, fields });
    const authorized = route.request().headers().authorization === 'Bearer access-token-two';
    if (!authorized) {
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(Buffer.alloc(0), 16)
      });
    }
    if (method === 'ListValues') {
      const selected = fields.get(1) || '/';
      const values = [...stored].filter(([path]) => parentPath(path) === selected);
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(listReply(values, existingPaths(stored)))
      });
    }
    if (method === 'GetSubTree') {
      if (delayedSubtree) {
        const delay = delayedSubtree;
        delayedSubtree = undefined;
        await delay.promise;
      }
      const selected = fields.get(1) || '/';
      const values = [...stored].filter(([path]) => (
        selected === '/' || path === selected || path.startsWith(`${selected}/`)
      ));
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(subtreeReply(values))
      });
    }
    if (method === 'PutValue') {
      const secret = fields.has(3);
      stored.set(fields.get(1), { value: fields.get(secret ? 3 : 2), secret });
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(mutationReply())
      });
    }
    if (method === 'ReplaceSubTree') {
      const selected = fields.get(1) || '/';
      for (const path of [...stored.keys()]) {
        if (!stored.get(path).secret && (selected === '/' || path === selected || path.startsWith(`${selected}/`))) {
          stored.delete(path);
        }
      }
      const replacements = repeatedMessages(body, 2);
      for (const value of replacements) {
        if (value.has(2)) stored.set(value.get(1), { value: value.get(2), secret: false });
      }
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(Buffer.concat([
          field(1, timestamp(1700000001)), scalarField(2, replacements.length)
        ]))
      });
    }
    if (method === 'RevealSecret') {
      const selected = fields.get(1);
      const value = stored.get(selected);
      const status = value?.secret ? 0 : (value ? 3 : 5);
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(status === 0 ? field(1, Buffer.from(value.value)) : Buffer.alloc(0), status)
      });
    }
    if (method !== 'DeleteValues') {
      throw new Error(`unexpected Configuration RPC ${method}`);
    }
    const selected = fields.get(1);
    const recurse = fields.get(2) === 1;
    let deleted = 0;
    for (const path of [...stored.keys()]) {
      if (path === selected || (recurse && (selected === '/' || path.startsWith(`${selected}/`)))) {
        stored.delete(path);
        deleted++;
      }
    }
    return route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(Buffer.concat([
        field(1, timestamp(1700000001)), scalarField(2, deleted)
      ]))
    });
  });
  return {
    requests,
    delayNextSubtree() {
      let release;
      const promise = new Promise(resolve => { release = resolve; });
      delayedSubtree = { promise };
      return release;
    },
    setValue(path, value, secret = false) {
      stored.set(path, { value, secret });
    },
    getValue(path) {
      return stored.get(path);
    }
  };
}

async function mockApplication(page) {
  await page.route('**/app-config.js', route => route.fulfill({
    contentType: 'text/javascript',
    body: configScript
  }));
  await page.route('**/sovereign.config.v3.System/GetVersion', route => {
    const application = Buffer.from('1.5.0');
    const protocol = Buffer.from('v3');
    const message = Buffer.concat([
      Buffer.from([0x0a, application.length]), application,
      Buffer.from([0x12, protocol.length]), protocol
    ]);
    return route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(message)
    });
  });
  await page.route('**/configuration/**', route => {
    if (route.request().resourceType() !== 'document') return route.continue();
    return route.fulfill({ contentType: 'text/html', path: path.join(staticDir, 'index.html') });
  });
}

async function mockDiscovery(page) {
  await page.route('**/.well-known/openid-configuration', route => route.fulfill({
    contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify({
      authorization_endpoint: 'https://auth.example.test/application/o/authorize/',
      token_endpoint: tokenEndpoint
    })
  }));
}

async function openCallback(
  page,
  refreshResult = 'success',
  state = 'expected-state',
  identityStatus = 0,
  expireRefresh = false
) {
  await page.addInitScript(({ expireRefresh }) => {
    sessionStorage.setItem('sovereign-config.pkce-state', 'expected-state');
    sessionStorage.setItem('sovereign-config.pkce-verifier', 'test-verifier');
    if (expireRefresh) {
      let now = Date.now();
      Date.now = () => now;
      const replaceState = history.replaceState.bind(history);
      history.replaceState = (...args) => {
        const result = replaceState(...args);
        now += 8 * 60 * 60 * 1000 + 1;
        return result;
      };
    }
  }, { expireRefresh });
  await mockDiscovery(page);
  await page.route('**/auth/callback?*', route => route.fulfill({
    contentType: 'text/html',
    path: path.join(staticDir, 'index.html')
  }));
  const tokenRequests = [];
  await page.route(tokenEndpoint, async route => {
    const form = new URLSearchParams(route.request().postData());
    tokenRequests.push(Object.fromEntries(form));
    if (form.get('grant_type') === 'authorization_code') {
      return route.fulfill({
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify({
          access_token: 'access-token-one',
          refresh_token: 'refresh-token-one',
          expires_in: 0.000001
        })
      });
    }
    if (refreshResult === 'rejected') {
      return route.fulfill({
        status: 400,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify({ error: 'invalid_grant' })
      });
    }
    if (refreshResult === 'unavailable') {
      return route.abort('connectionrefused');
    }
    if (refreshResult === 'transient') {
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify({ error: 'server_error' })
      });
    }
    return route.fulfill({
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': '*' },
      body: JSON.stringify({
        access_token: 'access-token-two',
        refresh_token: 'refresh-token-two',
        expires_in: 300
      })
    });
  });
  await page.route('**/sovereign.config.v3.System/GetIdentity', route => {
    const authorized = route.request().headers().authorization === 'Bearer access-token-two';
    const status = authorized ? identityStatus : 16;
    return route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(status === 0 ? Buffer.from([0x08, 0x01]) : Buffer.alloc(0), status)
    });
  });
  await page.goto(`/auth/callback?code=test-code&state=${state}`);
  return tokenRequests;
}

test.beforeEach(async ({ page }) => {
  await mockApplication(page);
});

test('reports service and logged-out state accessibly', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByText('Available')).toBeVisible();
  await expect(page.getByText('1.5.0')).toBeVisible();
  await expect(page.getByText('Logged out')).toBeVisible();

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
  expect(url.searchParams.get('scope')).toBe('openid sovereign-config offline_access');
  expect(url.searchParams.has('code_verifier')).toBe(false);
});

test('callback refreshes an expired access token and rotates the refresh token', async ({ page }) => {
  const requests = await openCallback(page);
  await expect(page.getByText('Logged in')).toBeVisible();
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
  await expect(page.getByText('Logged in')).toBeVisible();
  await page.getByRole('link', { name: 'Configuration values' }).click();
  await expect(page).toHaveURL(/\/configuration\/$/);
  await expect(page.getByRole('heading', { name: 'Configuration values' })).toBeVisible();
  await page.getByRole('link', { name: 'System status' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
});

test('refresh rejection clears the browser session', async ({ page }) => {
  await openCallback(page, 'rejected');
  await expect(page.getByText('Logged out')).toBeVisible();
  await expect(page.getByText('login has expired')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
  await expect.poll(() => storedRefreshState(page))
    .toEqual({ token: null, endpoint: null, expiry: null });
});

test('refresh outage does not reuse an expired access token', async ({ page }) => {
  await openCallback(page, 'unavailable');
  await expect(page.getByText('Unavailable', { exact: true })).toBeVisible();
  await expect(page.getByText('service is unavailable')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();
});

test('transient refresh HTTP failure preserves the browser session', async ({ page }) => {
  await openCallback(page, 'transient');
  await expect(page.getByText('Unavailable', { exact: true })).toBeVisible();
  await expect(page.getByText('identity provider is unavailable')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();
  await expect.poll(() => storedRefreshState(page)).toMatchObject({
    token: 'refresh-token-one',
    endpoint: tokenEndpoint
  });
});

test('absolute refresh expiry clears the browser session without a token request', async ({ page }) => {
  const requests = await openCallback(page, 'success', 'expected-state', 0, true);
  await expect(page.getByText('Logged out')).toBeVisible();
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
  await expect(page.getByText('Logged out')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Log in' })).toBeFocused();
});

test('callback rejects a mismatched state without exchanging the code', async ({ page }) => {
  const requests = await openCallback(page, 'success', 'wrong-state');
  await expect(page.getByText('Logged out')).toBeVisible();
  await expect(page.getByText('login response did not match this browser')).toBeVisible();
  expect(requests).toHaveLength(0);
});

test('reload restores the session with a rotated refresh token', async ({ page }) => {
  const requests = await openCallback(page);
  await expect(page.getByText('Logged in')).toBeVisible();
  await page.reload();
  await expect(page.getByText('Logged in')).toBeVisible();
  expect(requests).toHaveLength(3);
  expect(requests[2]).toMatchObject({
    grant_type: 'refresh_token',
    refresh_token: 'refresh-token-two'
  });
});

test('configuration path is deep-linked, selectable, and restored by browser history', async ({ page }) => {
  await openCallback(page);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
  await mockValues(page, {
    '/apps/api/feature-flag': 'enabled',
    '/apps/worker/concurrency': '4'
  });
  await page.goto('/configuration/apps/api');
  const pathInput = page.getByLabel('Selected path');
  await expect(pathInput).toHaveValue('/apps/api');
  await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();
  await expect(page.locator('#existing-paths [role="option"]')).toHaveCount(4);

  await pathInput.fill('/Apps/Worker');
  await page.getByRole('button', { name: 'Open' }).click();
  await expect(page).toHaveURL(/\/configuration\/apps\/worker$/);
  await expect(pathInput).toHaveValue('/apps/worker');
  await expect(page.getByRole('row', { name: /concurrency/ })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/configuration\/apps\/api$/);
  await expect(pathInput).toHaveValue('/apps/api');
  await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();
});

test('path selector refreshes external paths and Enter opens the selected path', async ({ page }) => {
  await openCallback(page);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
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

test('path selector popup uses the available viewport height', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await openCallback(page);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
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
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
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

test('JSON mode reads and replaces subtrees without exposing row deletion', async ({ page }) => {
  await openCallback(page);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
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
  await expect(page.getByRole('button', { name: 'Delete' })).toHaveCount(0);
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
  expect(requests.slice(-2).map(request => request.method)).toEqual([
    'ReplaceSubTree', 'GetSubTree'
  ]);

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
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
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
  await page.getByRole('link', { name: 'Configuration values' }).click();
  const pathInput = page.getByLabel('Selected path');

  await pathInput.fill('apps/bad_path');
  await expect(pathInput).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('path must begin with / and contain only letters, numbers, and hyphens')).toBeVisible();
  await expect(page).toHaveURL(/\/configuration\/$/);

  await pathInput.fill('/apps/new-area');
  await expect(pathInput).toHaveAttribute('aria-invalid', 'false');
  await page.getByRole('button', { name: 'Open' }).click();
  await expect(page).toHaveURL(/\/configuration\/apps\/new-area$/);
  await expect(page.getByText('No values at this path.')).toBeVisible();

  await page.getByRole('button', { name: 'Add value' }).click();
  const name = page.getByLabel('Name');
  await name.fill('bad_name');
  await expect(name).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('Name must contain only letters, numbers, and hyphens')).toBeVisible();
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
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
  const { requests } = await mockValues(page);
  await page.goto('/configuration/apps/api');
  await expect(page.getByText('No values at this path.')).toBeVisible();

  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Name').fill('Feature-Flag');
  await page.getByLabel('Value', { exact: true }).fill('plain-value-sentinel');
  await page.locator('#new-value-row').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  const editor = page.getByLabel('Value for feature-flag');
  await expect(editor).toHaveValue('plain-value-sentinel');
  expect(requests.at(-2).fields.get(1)).toBe('/apps/api/feature-flag');
  expect(requests.at(-2).fields.get(2)).toBe('plain-value-sentinel');

  await editor.fill('updated-value-sentinel');
  await page.getByRole('row', { name: /feature-flag/ }).getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Value for feature-flag')).toHaveValue('updated-value-sentinel');

  const row = page.getByRole('row', { name: /feature-flag/ });
  const remove = row.getByRole('button', { name: 'Delete' });
  await remove.click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('/apps/api/feature-flag')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(remove).toBeFocused();

  await remove.click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Deleted')).toBeVisible();
  await expect(page.getByText('No values at this path.')).toBeVisible();
  expect(requests.map(request => request.method)).toEqual([
    'ListValues', 'PutValue', 'ListValues', 'PutValue', 'ListValues', 'DeleteValues', 'ListValues'
  ]);
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
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
  const values = await mockValues(page, {
    '/apps/api/api-token': { value: originalSecret, secret: true },
    '/apps/api/enabled': 'true'
  });
  await page.goto('/configuration/apps/api');

  const row = page.getByRole('row', { name: /api-token/ });
  await expect(row.getByText('Secret', { exact: true })).toBeVisible();
  await expect(row.getByLabel('Secret value for api-token is hidden')).toHaveText('********');
  await expect(page.locator('body')).not.toContainText(originalSecret);

  const reveal = row.locator('button[aria-controls^="revealed-secret-"]');
  await reveal.focus();
  await page.keyboard.press('Enter');
  const revealed = page.getByLabel('Revealed secret for api-token');
  await expect(revealed).toHaveValue(originalSecret);
  await expect(revealed).toHaveAttribute('readonly', '');
  await expect(reveal).toHaveAttribute('aria-expanded', 'true');
  await reveal.focus();
  await page.keyboard.press('Enter');
  await expect(revealed).toBeHidden();
  await expect(revealed).toHaveValue('');

  const replacement = page.getByLabel('Replacement secret for api-token');
  const showReplacement = row.getByRole('button', { name: 'Show input' });
  await showReplacement.focus();
  await page.keyboard.press('Enter');
  await expect(replacement).toHaveAttribute('type', 'text');
  await page.keyboard.press('Enter');
  await expect(replacement).toHaveAttribute('type', 'password');
  await replacement.fill(rotatedSecret);
  await row.getByRole('button', { name: 'Replace' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  expect(values.getValue('/apps/api/api-token')).toEqual({ value: rotatedSecret, secret: true });
  await expect(page.locator('body')).not.toContainText(rotatedSecret);

  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Name').fill('Signing-Key');
  await page.getByLabel('Store as secret').check();
  const newSecret = page.getByLabel('Secret value', { exact: true });
  await expect(newSecret).toHaveAttribute('type', 'password');
  await newSecret.fill(addedSecret);
  await page.locator('#new-value-row').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  expect(values.getValue('/apps/api/signing-key')).toEqual({ value: addedSecret, secret: true });
  await expect(page.locator('body')).not.toContainText(addedSecret);

  const mode = page.getByRole('switch', { name: 'JSON' });
  await mode.check();
  const editor = page.getByLabel('JSON subtree');
  await expect(editor).toHaveValue(
    '{\n  "api-token": "********",\n  "enabled": "true",\n  "signing-key": "********"\n}\n'
  );
  await expect(editor).not.toHaveValue(new RegExp(`${rotatedSecret}|${addedSecret}`));
  await editor.fill('{"api-token":"********","enabled":"false","signing-key":"********"}');
  await page.getByRole('button', { name: 'Save JSON' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  expect(values.getValue('/apps/api/api-token')).toEqual({ value: rotatedSecret, secret: true });
  expect(values.getValue('/apps/api/signing-key')).toEqual({ value: addedSecret, secret: true });
  expect(values.getValue('/apps/api/enabled')).toEqual({ value: 'false', secret: false });

  await mode.uncheck();
  const refreshedRow = page.getByRole('row', { name: /api-token/ });
  await refreshedRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(page.getByLabel('Revealed secret for api-token')).toHaveValue(rotatedSecret);

  const failedPut = '**/sovereign.config.v3.Configuration/PutValue';
  await page.route(failedPut, route => route.fulfill({
    status: 200,
    headers: { 'content-type': 'application/grpc-web+proto' },
    body: grpcFrame(Buffer.alloc(0), 7)
  }));
  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Name').fill('failed-value');
  await page.getByLabel('Value', { exact: true }).fill('never-stored');
  await page.locator('#new-value-row').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('permission denied', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Revealed secret for api-token')).toBeHidden();
  await expect(page.getByLabel('Revealed secret for api-token')).toHaveValue('');
  await page.unroute(failedPut);
  await page.locator('#new-value-row').getByRole('button', { name: 'Cancel' }).click();

  await refreshedRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(page.getByLabel('Revealed secret for api-token')).toHaveValue(rotatedSecret);
  await page.reload();
  await expect(page.getByRole('row', { name: /api-token/ })).toBeVisible();
  await expect(page.getByLabel('Revealed secret for api-token')).toBeHidden();
  await expect(page.getByLabel('Revealed secret for api-token')).toHaveValue('');
  await expect(page.locator('body')).not.toContainText(rotatedSecret);

  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Name').fill('unsubmitted-secret');
  await page.getByLabel('Store as secret').check();
  await page.getByLabel('Secret value', { exact: true }).fill(unsubmittedSecret);
  await page.getByRole('link', { name: 'System status' }).click();
  await expect(page.locator('body')).not.toContainText(unsubmittedSecret);
  await page.goBack();
  await expect(page.getByRole('row', { name: /api-token/ })).toBeVisible();
  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Store as secret').check();
  await expect(page.getByLabel('Secret value', { exact: true })).toHaveValue('');
  await page.locator('#new-value-row').getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('row', { name: /api-token/ }).getByRole('button', { name: 'Reveal' }).click();
  await expect(page.getByLabel('Revealed secret for api-token')).toHaveValue(rotatedSecret);
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

  await page.getByRole('link', { name: 'Configuration values' }).click();
  await page.getByRole('button', { name: 'Add value' }).click();
  await page.getByLabel('Name').fill('foo');
  await page.getByLabel('Value', { exact: true }).fill('bar');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('permission denied', { exact: true })).toBeVisible();
});

for (const contract of transportContract) {
  test(`browser transport maps gRPC status ${contract.grpc_status}`, async ({ page }) => {
    const requests = await openCallback(page, 'success', 'expected-state', contract.grpc_status);
    if (contract.grpc_status === 0) {
      await expect(page.getByText('Logged in')).toBeVisible();
      return;
    }
    await expect(page.getByText(contract.message, { exact: true })).toBeVisible();
    const authentication = contract.grpc_status === 16 ? 'Logged out' : 'Unavailable';
    await expect(page.getByText(authentication, { exact: true })).toBeVisible();
    if (contract.grpc_status === 16) {
      await expect.poll(() => storedRefreshState(page))
        .toEqual({ token: null, endpoint: null, expiry: null });
      await page.reload();
      await expect(page.getByText('Logged out')).toBeVisible();
      expect(requests).toHaveLength(2);
    }
  });
}
