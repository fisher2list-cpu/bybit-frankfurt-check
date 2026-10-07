import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeServer, probe } from './server.mjs';

test('market time must be valid JSON with successful Bybit status', async () => {
  assert.equal((await probe('market', async () => Response.json({ retCode: 0, result: { timeSecond: '123' } }))).reachable, true);
  assert.equal((await probe('market', async () => Response.json({ retCode: 10001 }))).reachable, false);
  assert.equal((await probe('market', async () => new Response('<html>error</html>'))).reachable, false);
  assert.equal((await probe('market', async () => Response.json(null))).reachable, false);
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
