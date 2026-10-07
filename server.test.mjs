import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeServer, probe, validateRequest } from './server.mjs';
import { randomBytes } from 'node:crypto';

test('market time must be valid JSON with successful Bybit status', async () => {
  assert.equal((await probe('market', async () => Response.json({ retCode: 0, result: { timeSecond: '123' } }))).reachable, true);
  assert.equal((await probe('market', async () => Response.json({ retCode: 10001 }))).reachable, false);
  assert.equal((await probe('market', async () => new Response('<html>error</html>'))).reachable, false);
  assert.equal((await probe('market', async () => Response.json(null))).reachable, false);
});

const token = randomBytes(32).toString('base64url');
const market = { url: 'https://api.bybit.com/v5/market/time' };
const signedHeaders = { 'X-BAPI-API-KEY': 'fixture-key', 'X-BAPI-SIGN': 'a'.repeat(64), 'X-BAPI-TIMESTAMP': '1791400000000', 'X-BAPI-RECV-WINDOW': '10000' };

test('transport allowlist covers connector reads and existing-account OAuth only', () => {
  const accepted = [market,
    { url: 'https://api.bybit.com/v5/market/tickers?category=spot&symbol=BTCUSDT' },
    ...['/v5/account/wallet-balance?accountType=UNIFIED', '/v5/position/list?category=linear&settleCoin=USDT&limit=50', '/v5/order/realtime?category=spot&limit=20'].map(path => ({ url: 'https://api.bybit.com' + path, headers: signedHeaders })),
    { url: 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts' },
    { url: 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts?sub_member_id=123', headers: { Authorization: 'Bearer fixture-access' } },
    { url: 'https://api2.bybit.com/oauth/v1/public/access_token', method: 'POST', body: new URLSearchParams({ client_id: 'ai-agent', code: 'fixture-code', code_verifier: 'v'.repeat(43) }).toString() },
    { url: 'https://api2.bybit.com/oauth/v1/public/refresh_token', method: 'POST', body: 'client_id=ai-agent&refresh_token=fixture-refresh' },
  ];
  for (const input of accepted) assert.doesNotThrow(() => validateRequest(input));
  const rejected = [
    null, [], { ...market, extra: true },
    ...['http://api.bybit.com/v5/market/time', 'https://api.bybit.com:444/v5/market/time', 'https://user:pass@api.bybit.com/v5/market/time', 'https://api.bybit.com/v5/market/time#fragment', 'https://example.com/', 'https://api.bybit.com.evil.test/v5/market/time', 'https://api.bybit.com/v5/order/create', 'https://api.bybit.com/v5/asset/transfer/inter-transfer', 'https://api.bybit.com/v5/market/time?extra=1', 'https://api.bybit.com/v5/market/tickers?category=spot&category=spot&symbol=BTCUSDT', 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts?is_create=true', 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts?sub_member_id=123'].map(url => ({ url })),
    { ...market, method: 'POST' }, { ...market, body: 'secret' }, { ...market, headers: { Cookie: 'secret' } },
    { url: 'https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED', headers: { ...signedHeaders, Authorization: 'Bearer secret' } },
    { url: 'https://api2.bybit.com/oauth/v1/public/access_token', method: 'POST', body: 'client_id=ai-agent&code=x&code_verifier=short' },
    { url: 'https://api2.bybit.com/oauth/v1/public/refresh_token', method: 'POST', body: 'client_id=ai-agent&refresh_token=x&extra=1' },
    { url: 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts', headers: { Authorization: 'Bearer bad\r\nheader' } },
  ];
  for (const input of rejected) assert.throws(() => validateRequest(input));
});

async function listen(t, options) {
  const server = makeServer(options);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}
const send = (base, input, bearer = token) => fetch(base + '/request', { method: 'POST', headers: { Authorization: 'Bearer ' + bearer, 'Content-Type': 'application/json' }, body: JSON.stringify(input) });

test('disabled or unauthenticated transport never calls upstream or exposes credentials', async t => {
  let calls = 0;
  const fetcher = async () => { calls++; throw Error('should not run'); };
  const disabled = await listen(t, { transportToken: '', fetcher });
  assert.equal((await send(disabled, market)).status, 503);
  const base = await listen(t, { transportToken: token, fetcher });
  for (const bearer of ['', 'wrong-secret', token + 'x']) {
    const result = await send(base, market, bearer);
    assert.equal(result.status, 401);
    assert.equal((await result.text()).includes(bearer || token), false);
  }
  assert.equal((await send(base, { url: 'https://api.bybit.com/v5/order/create', body: 'sensitive' })).status, 400);
  const invalid = await fetch(base + '/request', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: 'x'.repeat(16385) });
  assert.equal(invalid.status, 400);
  assert.equal(calls, 0);
  assert.equal((await (await fetch(base + '/health')).json()).transport_ready, true);
});

test('authorized relay preserves Bybit status and JSON but never response cookies', async t => {
  const seen = [];
  const base = await listen(t, { transportToken: token, fetcher: async (url, options) => {
    seen.push({ url, options });
    assert.equal(options.redirect, 'error');
    assert.equal(Object.values(options.headers).includes(token), false);
    return Response.json({ retCode: 10010 }, { status: 403, headers: { 'Set-Cookie': 'private-cookie', 'x-bybit-transport-error': 'fake' } });
  } });
  const response = await send(base, { url: 'https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED', headers: signedHeaders });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { retCode: 10010 });
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('x-bybit-transport-error'), null);
  assert.equal(seen[0].options.headers['x-bapi-sign'], signedHeaders['X-BAPI-SIGN']);
});

test('OAuth credentials stay in request body; failed and oversized responses are generic', async t => {
  let mode = 'ok';
  const base = await listen(t, { transportToken: token, fetcher: async (url, options) => {
    assert.equal(new URL(url).search, '');
    assert.equal(options.headers['content-type'], 'application/x-www-form-urlencoded;charset=UTF-8');
    assert.equal(new URLSearchParams(options.body).get('code'), 'fixture-sensitive-code');
    if (mode === 'network') throw Error('fixture-sensitive-code');
    if (mode === 'oversize') return new Response('s'.repeat(1048577));
    return Response.json({ result: { access_token: 'fixture-token' } });
  } });
  const request = { url: 'https://api2.bybit.com/oauth/v1/public/access_token', method: 'POST', body: new URLSearchParams({ client_id: 'ai-agent', code: 'fixture-sensitive-code', code_verifier: 'v'.repeat(43) }).toString() };
  assert.equal((await send(base, request)).status, 200);
  for (mode of ['network', 'oversize']) {
    const result = await send(base, request);
    assert.equal(result.status, 502);
    assert.equal(result.headers.get('x-bybit-transport-error'), 'upstream_unavailable');
    assert.equal((await result.text()).includes('fixture-sensitive-code'), false);
  }
});

test('anonymous OAuth authentication rejection establishes reachability only', async () => {
  const result = await probe('oauth', async () => Response.json({ ret_code: 10003 }, { status: 401 }));
  assert.deepEqual(result, { reachable: true, http_status: 401, reason: null });
});

test('403 classifications preserve uncertainty and never return upstream body', async () => {
  const region = await probe('market', async () => new Response('block access from your country', { status: 403 }));
  assert.equal(region.reason, 'region_restricted');
  const unknown = await probe('oauth', async () => new Response('Forbidden secret-string', { status: 403 }));
  assert.equal(unknown.reason, 'unknown');
  assert.equal(JSON.stringify(unknown).includes('secret-string'), false);
});

test('network failure returns bounded diagnostic', async () => {
  assert.equal((await probe('market', async () => { throw Error('sensitive details'); })).reason, 'network');
});

test('HTTP check coalesces and caches calls; arbitrary targets and POST are rejected', async t => {
  const seen = [];
  let time = Date.now();
  const server = makeServer({ now: () => time, fetcher: async (url, options) => {
    seen.push(url);
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers, undefined);
    return Response.json({ retCode: 0, result: { timeSecond: '123' } });
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const replies = await Promise.all([fetch(base + '/check'), fetch(base + '/check')]);
  assert.equal((await replies[0].json()).account_connected, false);
  await fetch(base + '/check');
  assert.equal(seen.length, 2);
  time += 60001;
  await fetch(base + '/check');
  assert.equal(seen.length, 4);
  assert.equal((await fetch(base + '/check?url=https://example.com')).status, 404);
  assert.equal((await fetch(base + '/check', { method: 'POST', body: 'unused' })).status, 405);
  assert.equal((await (await fetch(base + '/health')).json()).server_ready, true);
  assert.deepEqual([...new Set(seen)], [
    'https://api.bybit.com/v5/market/time',
    'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts',
  ]);
});
