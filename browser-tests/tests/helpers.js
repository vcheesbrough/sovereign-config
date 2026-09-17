const { expect } = require('@playwright/test');
const path = require('node:path');

const configScript = 'globalThis.SOVEREIGN_CONFIG={issuer:"https://auth.example.test/application/o/sovereign-config/",clientId:"sovereign-config"};';
const staticDir = process.env.PLAYWRIGHT_STATIC_DIR
  ? path.resolve(process.env.PLAYWRIGHT_STATIC_DIR)
  : path.resolve(__dirname, '../../web-dist');
const tokenEndpoint = 'https://auth.example.test/application/o/token/';

// The header no longer narrates the session in words: the button on offer is
// the statement. Log out on show means signed in, Log in means signed out.
function signedIn(page) {
  return page.getByRole('button', { name: 'Log out' });
}

function signedOut(page) {
  return page.getByRole('button', { name: 'Log in' });
}

// Access URLs, Downloads and Configuration values are reached through the
// brand-mark menu rather than a sidebar nav strip.
async function openView(page, name) {
  await page.getByRole('button', { name: 'Sovereign Config' }).click();
  await page.getByRole('link', { name, exact: true }).click();
}

// The mutation sequence a view issued, with the listings that precede the
// first mutation dropped. The app lands on the configuration root as soon as
// the session is established and lists it, so how many listings come before a
// deep link is opened is a matter of timing, not of behaviour worth asserting
// — but that there is at least one, before anything else, is: it is the grid
// reading its path before it ever mutates it. GetSubTree is excluded
// throughout: that is the sidebar tree's own whole-estate read, not part of
// any grid sequence.
function mutationSequence(requests) {
  const methods = requests
    .map(request => request.method)
    .filter(method => method !== 'GetSubTree');
  expect(methods[0], 'expected the view to list its path before mutating it').toBe('ListValues');
  const first = methods.findIndex(method => method !== 'ListValues');
  expect(first, 'expected the flow to issue at least one mutation').toBeGreaterThan(-1);
  return methods.slice(first);
}

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
    scalarField(6, value.secret ? 2 : 1),
    ...(value.aliases || []).map(alias => field(7, Buffer.from(alias)))
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

// Decodes a repeated varint field, accepting both packed (wire type 2, a
// single length-delimited chunk — how prost encodes repeated enums) and
// unpacked (wire type 0, one entry per value) encodings.
function decodeRepeatedVarints(values) {
  const out = [];
  for (const value of values) {
    if (Buffer.isBuffer(value)) {
      let offset = 0;
      while (offset < value.length) {
        const [decoded, next] = readVarint(value, offset);
        out.push(decoded);
        offset = next;
      }
    } else {
      out.push(value);
    }
  }
  return out;
}

// The permission enums selected for field 3 of a captured
// CreateManagedConnection request, in the order they were sent.
function requestPermissions(request) {
  return decodeRepeatedVarints(messageFields(request.body, 5).get(3) || []);
}

function parentPath(path) {
  const split = path.lastIndexOf('/');
  return split <= 0 ? '/' : path.slice(0, split);
}

// The real server resolves paths case-insensitively while returning them in
// whatever case they were stored with (card #294); this mock has to do the
// same fold comparison or a route built from a tree node's fold-only
// `data-path` (e.g. "/zone/alpha") would never match a stored path whose
// case differs (e.g. "/Zone/alpha/one").
function foldEquals(left, right) {
  return left.toLowerCase() === right.toLowerCase();
}

function isAtOrBelowFold(path, selected) {
  if (selected === '/') return true;
  const folded = path.toLowerCase();
  const selectedFolded = selected.toLowerCase();
  return folded === selectedFolded || folded.startsWith(`${selectedFolded}/`);
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
  let delayedReveal;
  let delayedAddPath;
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
      const values = [...stored].filter(([path]) => foldEquals(parentPath(path), selected));
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
      const values = [...stored].filter(([path]) => isAtOrBelowFold(path, selected));
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
      if (delayedReveal) {
        const delay = delayedReveal;
        delayedReveal = undefined;
        await delay.promise;
      }
      const selected = fields.get(1);
      const value = stored.get(selected);
      const status = value?.secret ? 0 : (value ? 3 : 5);
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(status === 0 ? field(1, Buffer.from(value.value)) : Buffer.alloc(0), status)
      });
    }
    if (method === 'AddValuePath') {
      if (delayedAddPath) {
        const delay = delayedAddPath;
        delayedAddPath = undefined;
        await delay.promise;
      }
      const source = fields.get(1);
      const added = fields.get(2);
      const value = stored.get(source);
      if (!value) {
        return route.fulfill({
          status: 200,
          headers: { 'content-type': 'application/grpc-web+proto' },
          body: grpcFrame(Buffer.alloc(0), 5)
        });
      }
      // One value, many paths: record the new path as another alias of the
      // same stored value rather than copying its content.
      value.aliases = [...(value.aliases || []), added].sort();
      return route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: grpcFrame(field(1, timestamp(1700000002)))
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
    // Removing an alias path deletes only that path; the value survives via its
    // primary path, so drop the alias rather than the whole entry.
    if (deleted === 0) {
      for (const value of stored.values()) {
        if (value.aliases && value.aliases.includes(selected)) {
          value.aliases = value.aliases.filter(alias => alias !== selected);
          deleted++;
        }
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
    delayNextReveal() {
      let release;
      const promise = new Promise(resolve => { release = resolve; });
      delayedReveal = { promise };
      return release;
    },
    delayNextAddPath() {
      let release;
      const promise = new Promise(resolve => { release = resolve; });
      delayedAddPath = { promise };
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
  // The sidebar tree reads the whole configuration and the connection list on
  // every load, including on views a test is not otherwise exercising. These
  // empty replies keep those reads off the network; Playwright matches routes in
  // reverse registration order, so mockValues/mockConnections still win.
  for (const service of ['Configuration', 'ManagedConnections']) {
    await page.route(`**/sovereign.config.v3.${service}/*`, route => route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(Buffer.alloc(0))
    }));
  }
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
  await page.route('**/connections/**', route => {
    if (route.request().resourceType() !== 'document') return route.continue();
    return route.fulfill({ contentType: 'text/html', path: path.join(staticDir, 'index.html') });
  });
}

const CONNECTION_ID = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
const APP_PASSWORD_SENTINEL = 'browser-app-password-sentinel';

// The URL's path is the connection's root; the client rejects a provisioned URL
// whose root disagrees with the returned metadata, exactly as the service would.
function connectionUrl(password = APP_PASSWORD_SENTINEL, root = '/apps/api') {
  const credential = Buffer.from(`sc-managed-${CONNECTION_ID}:${password}`)
    .toString('base64url');
  const issuer = encodeURIComponent('https://auth.example.test/application/o/config/');
  return `https://config.example.test${root === '/' ? '' : root}#v=1&issuer=${issuer}`
    + `&client_id=sovereign-config&client_secret=${credential}`;
}

function connectionMetadata({ id = CONNECTION_ID, name = 'Pipeline reader', root = '/apps/api', state = 2, permissions = [1] } = {}) {
  const instant = timestamp(1700000000);
  return Buffer.concat([
    field(1, Buffer.from(id)),
    field(2, Buffer.from(name)),
    field(3, Buffer.from(root)),
    scalarField(4, state),
    field(5, instant),
    field(6, instant),
    ...permissions.map(permission => scalarField(7, permission))
  ]);
}

function listConnectionsReply(connections) {
  return Buffer.concat(connections.map(connection => field(1, connectionMetadata(connection))));
}

function provisionedReply(url, connection = {}) {
  return Buffer.concat([
    field(1, connectionMetadata(connection)),
    field(2, Buffer.from(url))
  ]);
}

/**
 * Mocks the ManagedConnections service. `script` may override the status or
 * body of any method to exercise failure and ambiguity paths.
 */
async function mockConnections(page, options = {}) {
  const state = {
    connections: options.connections || [{}],
    requests: [],
    script: options.script || {},
    rotations: 0
  };
  let delayedList;
  await page.route('**/sovereign.config.v3.ManagedConnections/*', async route => {
    const method = route.request().url().split('/').pop();
    const body = route.request().postDataBuffer();
    const fields = stringFields(body);
    state.requests.push({ method, fields, body });
    const authorized = route.request().headers().authorization === 'Bearer access-token-two';
    const reply = (body, status = 0) => route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: grpcFrame(body, status)
    });
    if (!authorized) return reply(Buffer.alloc(0), 16);
    const scripted = state.script[method];
    if (typeof scripted === 'number') return reply(Buffer.alloc(0), scripted);
    if (typeof scripted === 'function') {
      const outcome = scripted(state);
      if (typeof outcome === 'number') return reply(Buffer.alloc(0), outcome);
      if (outcome) return reply(outcome);
    }
    if (method === 'ListManagedConnections') {
      if (delayedList) {
        const delay = delayedList;
        delayedList = undefined;
        await delay.promise;
      }
      return reply(listConnectionsReply(state.connections));
    }
    if (method === 'CreateManagedConnection') {
      const permissions = requestPermissions({ body });
      const created = {
        name: fields.get(1),
        root: fields.get(2),
        ...(permissions.length ? { permissions } : {})
      };
      state.connections = [...state.connections, created];
      return reply(provisionedReply(connectionUrl(APP_PASSWORD_SENTINEL, created.root), created));
    }
    if (method === 'RotateManagedConnection') {
      state.rotations += 1;
      return reply(provisionedReply(connectionUrl(`rotated-password-${state.rotations}`)));
    }
    if (method === 'RevokeManagedConnection') {
      state.connections = [];
      return reply(Buffer.alloc(0));
    }
    return reply(Buffer.alloc(0), 2);
  });
  state.delayNextList = () => {
    let release;
    const promise = new Promise(resolve => { release = resolve; });
    delayedList = { promise };
    return release;
  };
  return state;
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

// An unsigned ID token in the shape Authentik returns. The app decodes it for
// a display name only and never treats it as proof of anything, so a real
// signature would assert nothing the tests could check.
function idToken(claims) {
  const payload = Buffer.from(JSON.stringify(claims))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `header.${payload}.signature`;
}

async function openCallback(
  page,
  refreshResult = 'success',
  state = 'expected-state',
  identityStatus = 0,
  expireRefresh = false,
  claims = { sub: 'operator-subject', preferred_username: 'avc', name: 'A Vincent' }
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
          id_token: claims ? idToken(claims) : undefined,
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

const TREE_VALUES = {
  '/apps/api/enabled': 'true',
  '/apps/api/nested/message': 'hello',
  '/apps/worker/concurrency': '4',
  '/top-level': 'value'
};

function treeNode(page, path) {
  return page.locator(`#config-tree [data-path="${path}"]`);
}

async function openConfiguration(page) {
  await openView(page, 'Configuration values');
  await expect(page).toHaveURL(/\/configuration\/$/);
}

module.exports = {
  configScript,
  staticDir,
  tokenEndpoint,
  signedIn,
  signedOut,
  openView,
  mutationSequence,
  storedRefreshState,
  grpcFrame,
  varint,
  field,
  timestamp,
  mutationReply,
  scalarField,
  storedValue,
  subTreeValue,
  subtreeReply,
  listedValue,
  listReply,
  readVarint,
  messageFields,
  stringFields,
  nestedStringFields,
  repeatedMessages,
  decodeRepeatedVarints,
  requestPermissions,
  parentPath,
  foldEquals,
  isAtOrBelowFold,
  existingPaths,
  mockValues,
  mockApplication,
  CONNECTION_ID,
  APP_PASSWORD_SENTINEL,
  connectionUrl,
  connectionMetadata,
  listConnectionsReply,
  provisionedReply,
  mockConnections,
  mockDiscovery,
  idToken,
  openCallback,
  TREE_VALUES,
  treeNode,
  openConfiguration
};
