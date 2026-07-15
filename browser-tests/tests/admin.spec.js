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

function valueReply(value) {
  const instant = timestamp(1700000000);
  return Buffer.concat([
    field(1, Buffer.from(value)),
    field(2, instant),
    field(3, instant)
  ]);
}

function mutationReply() {
  const instant = timestamp(1700000000);
  return Buffer.concat([field(1, instant), field(2, instant)]);
}

function listedValue(path, value) {
  const instant = timestamp(1700000000);
  return Buffer.concat([
    field(1, Buffer.from(path)),
    field(2, Buffer.from(value)),
    field(3, instant),
    field(4, instant)
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

function stringFields(frame) {
  const fields = new Map();
  let offset = 5;
  while (offset < frame.length) {
    const [tag, afterTag] = readVarint(frame, offset);
    offset = afterTag;
    const [length, afterLength] = readVarint(frame, offset);
    offset = afterLength;
    fields.set(tag >> 3, frame.subarray(offset, offset + length).toString());
    offset += length;
  }
  return fields;
}

function parentPath(path) {
  const split = path.lastIndexOf('/');
  return split === -1 ? '' : path.slice(0, split);
}

function existingPaths(values) {
  const paths = new Set();
  for (const path of values.keys()) {
    const parent = parentPath(path);
    if (parent === '') {
      paths.add('');
      continue;
    }
    const segments = parent.split('/');
    for (let index = 1; index <= segments.length; index++) {
      paths.add(segments.slice(0, index).join('/'));
    }
  }
  return [...paths].sort();
}

async function mockValues(page, initial = {}) {
  const stored = new Map(Object.entries(initial));
  const requests = [];
  await page.route('**/sovereign.config.v1.Configuration/*', route => {
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
      const selected = fields.get(1) || '';
      const values = [...stored].filter(([path]) => parentPath(path) === selected);
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(listReply(values, existingPaths(stored)))
      });
    }
    if (method === 'GetValue') {
      const value = stored.get(fields.get(1));
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: value === undefined ? grpcFrame(Buffer.alloc(0), 5) : grpcFrame(valueReply(value))
      });
    }
    if (method === 'PutValue') {
      stored.set(fields.get(1), fields.get(2));
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(mutationReply())
      });
    }
    stored.delete(fields.get(1));
    return route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(field(1, timestamp(1700000001)))
    });
  });
  return {
    requests,
    setValue(path, value) {
      stored.set(path, value);
    }
  };
}

async function mockApplication(page) {
  await page.route('**/app-config.js', route => route.fulfill({
    contentType: 'text/javascript',
    body: configScript
  }));
  await page.route('**/sovereign.config.v1.System/GetVersion', route => {
    const application = Buffer.from('1.3.0');
    const protocol = Buffer.from('v1');
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
  await page.route('**/sovereign.config.v1.System/GetIdentity', route => {
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
  await expect(page.getByText('1.3.0')).toBeVisible();
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
    'apps/api/feature-flag': 'enabled',
    'apps/worker/concurrency': '4'
  });
  await page.goto('/configuration/apps/api');
  const pathInput = page.getByLabel('Selected path');
  await expect(pathInput).toHaveValue('/apps/api');
  await expect(page.getByRole('row', { name: /feature-flag/ })).toBeVisible();
  await expect(page.locator('#existing-paths option')).toHaveCount(4);

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
    'apps/api/feature-flag': 'enabled'
  });
  await page.goto('/configuration/apps/api');
  const pathInput = page.getByLabel('Selected path');
  await expect(page.locator('#existing-paths option[value="/services/worker"]')).toHaveCount(0);

  values.setValue('services/worker/concurrency', '4');
  await pathInput.focus();
  await expect(page.locator('#existing-paths option[value="/services/worker"]')).toHaveCount(1);

  await pathInput.fill('/services/worker');
  await pathInput.press('Enter');
  await expect(page).toHaveURL(/\/configuration\/services\/worker$/);
  await expect(page.getByRole('row', { name: /concurrency/ })).toBeVisible();
});

test('configuration grid is accessible and contained on desktop and mobile', async ({ page }, testInfo) => {
  await openCallback(page);
  await expect(page.getByText('Logged in', { exact: true })).toBeVisible();
  await mockValues(page, {
    'apps/api/feature-flag': 'enabled',
    'apps/api/retry-limit': '5'
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
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  const editor = page.getByLabel('Value for feature-flag');
  await expect(editor).toHaveValue('plain-value-sentinel');
  expect(requests.at(-2).fields.get(1)).toBe('apps/api/feature-flag');
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
    'ListValues', 'PutValue', 'ListValues', 'PutValue', 'ListValues', 'DeleteValue', 'ListValues'
  ]);
});

test('trailers-only save errors retain their bounded gRPC status', async ({ page }) => {
  await openCallback(page);
  await mockValues(page);
  await page.route('**/sovereign.config.v1.Configuration/PutValue', route => route.fulfill({
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
