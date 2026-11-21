const { test, expect } = require('@playwright/test');
const {
  signedIn,
  mockValues,
  mockApplication,
  negotiate,
  openCallback,
  openConfiguration,
  messageFields,
  refuse,
  CONNECT,
  GRPC_WEB
} = require('./helpers');

// Which version the page speaks, and on which wire: the handshake is always
// Connect; `v6` travels Connect, `v3`–`v5` gRPC-Web. The mocks answer in the
// shape of each request, so these tests assert on what the page sent.

const VALUES = { '/apps/api/enabled': 'true' };

// Every call the page made to the service, with what identifies its wire.
function recordCalls(page) {
  const calls = [];
  page.on('request', request => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith('/sovereign.config.')) return;
    calls.push({
      path: url.pathname,
      method: url.pathname.split('/').pop(),
      contentType: request.headers()['content-type'],
      connectVersion: request.headers()['connect-protocol-version'],
      body: request.postDataBuffer() || Buffer.alloc(0)
    });
  });
  return calls;
}

async function openPath(page, selected) {
  await page.getByLabel('Selected path').fill(selected);
  await page.getByRole('button', { name: 'Open' }).click();
}

test.describe('protocol', () => {
  test.beforeEach(async ({ page }) => {
    await mockApplication(page);
  });

  test('the page negotiates v6 and dials it over Connect', async ({ page }) => {
    const calls = recordCalls(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openConfiguration(page);
    await openPath(page, '/apps/api');
    await expect(page.getByLabel('Value for enabled')).toHaveValue('true');

    // The handshake is Connect: the bare NegotiateRequest, no gRPC-Web frame,
    // offering every version the page speaks, newest first.
    const handshake = calls.find(call => call.path === '/sovereign.config.Handshake/Negotiate');
    expect(handshake).toBeTruthy();
    expect(handshake.contentType).toBe(CONNECT);
    expect(handshake.connectVersion).toBe('1');
    const offered = (messageFields(handshake.body).get(1) || []).map(value => value.toString());
    expect(offered).toEqual(['v6', 'v5', 'v4', 'v3']);

    // Every versioned call went to v6, over Connect, as a bare message.
    const versioned = calls.filter(call => call !== handshake);
    expect(versioned.map(call => call.method)).toEqual(expect.arrayContaining(['GetVersion', 'ListValues']));
    for (const call of versioned) {
      expect(call.path).toMatch(/^\/sovereign\.config\.v6\./);
      expect(call.contentType).toBe(CONNECT);
      expect(call.connectVersion).toBe('1');
    }
    const listing = versioned.filter(call => call.method === 'ListValues').at(-1);
    expect(messageFields(listing.body).get(1).map(value => value.toString())).toEqual(['/apps/api']);
  });

  test('a service offering only v5 is dialled over gRPC-Web', async ({ page }) => {
    await negotiate(page, 'v5');
    const calls = recordCalls(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openConfiguration(page);
    await openPath(page, '/apps/api');
    await expect(page.getByLabel('Value for enabled')).toHaveValue('true');

    const handshake = calls.find(call => call.path === '/sovereign.config.Handshake/Negotiate');
    expect(handshake.contentType).toBe(CONNECT);
    const versioned = calls.filter(call => call !== handshake);
    expect(versioned.map(call => call.method)).toEqual(expect.arrayContaining(['GetVersion', 'ListValues']));
    for (const call of versioned) {
      expect(call.path).toMatch(/^\/sovereign\.config\.v5\./);
      expect(call.contentType).toBe(GRPC_WEB);
      expect(call.connectVersion).toBeUndefined();
    }
  });

  test('a v6 call refused as version-not-served over Connect re-negotiates and retries', async ({ page }) => {
    const calls = recordCalls(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openConfiguration(page);

    // The service stops serving v6: its routes answer with the marker in a
    // header, and the handshake now offers v5 alone.
    await negotiate(page, 'v5');
    await page.route('**/sovereign.config.v6.*/*', route =>
      refuse(route, 9, { kind: 'version-not-served' }));
    calls.length = 0;
    await openPath(page, '/apps/api');
    await expect(page.getByLabel('Value for enabled')).toHaveValue('true');
    await expect(page.locator('#error')).toBeHidden();

    const listings = calls.filter(call => call.method === 'ListValues');
    expect(listings[0].path).toBe('/sovereign.config.v6.Configuration/ListValues');
    expect(listings.at(-1).path).toBe('/sovereign.config.v5.Configuration/ListValues');
    expect(listings.at(-1).contentType).toBe(GRPC_WEB);
    expect(calls.some(call => call.path === '/sovereign.config.Handshake/Negotiate')).toBe(true);
  });
});
