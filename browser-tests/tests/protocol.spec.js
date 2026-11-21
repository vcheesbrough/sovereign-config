const { test, expect } = require('@playwright/test');
const {
  signedIn,
  mockValues,
  mockApplication,
  negotiate,
  openCallback,
  openConfiguration,
  treeNode,
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

// Whether the page's calls to the service have gone quiet: none in flight,
// and none started or finished for a short stretch. A view opens with a
// chain of calls, each started when the one before it answers, so "none in
// flight" alone can be read in the gap between two links.
function serviceTraffic(page) {
  let pending = 0;
  let lastActivity = Date.now();
  const service = request => new URL(request.url()).pathname.startsWith('/sovereign.config.');
  const started = request => {
    if (!service(request)) return;
    pending += 1;
    lastActivity = Date.now();
  };
  const ended = request => {
    if (!service(request)) return;
    pending -= 1;
    lastActivity = Date.now();
  };
  page.on('request', started);
  page.on('requestfinished', ended);
  page.on('requestfailed', ended);
  return { quiet: () => pending === 0 && Date.now() - lastActivity >= 250 };
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
    const traffic = serviceTraffic(page);
    await openCallback(page);
    await expect(signedIn(page)).toBeVisible();
    await mockValues(page, VALUES);
    await openConfiguration(page);
    // Opening the view starts its own calls (the listing, then what follows
    // from it). Let them all answer on v6 first: one still in flight when the
    // routes change below would be refused, and the page would re-negotiate
    // to v5 before the call this test is about is made.
    await expect(treeNode(page, '/apps/api')).toBeVisible();
    await expect.poll(traffic.quiet).toBe(true);

    // The service stops serving v6: its routes answer with the marker in a
    // header, and the handshake now offers v5 alone.
    await negotiate(page, 'v5');
    await page.route('**/sovereign.config.v6.*/*', route =>
      refuse(route, 9, { kind: 'version-not-served' }));
    calls.length = 0;
    await openPath(page, '/apps/api');
    await expect(page.getByLabel('Value for enabled')).toHaveValue('true');
    await expect(page.locator('#error')).toBeHidden();

    // The listing was tried on v6, refused, re-negotiated, and retried on v5
    // over gRPC-Web: in that order.
    const listings = calls.filter(call => call.method === 'ListValues');
    expect(listings[0].path).toBe('/sovereign.config.v6.Configuration/ListValues');
    expect(listings.at(-1).path).toBe('/sovereign.config.v5.Configuration/ListValues');
    expect(listings.at(-1).contentType).toBe(GRPC_WEB);
    const handshake = calls.findIndex(call => call.path === '/sovereign.config.Handshake/Negotiate');
    expect(handshake).toBeGreaterThan(calls.indexOf(listings[0]));
    expect(handshake).toBeLessThan(calls.indexOf(listings.at(-1)));
  });
});
