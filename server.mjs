import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { timingSafeEqual } from 'node:crypto';

const endpoints = {
  market: 'https://api.bybit.com/v5/market/time',
  oauth: 'https://api2.bybit.com/oauth/v1/resource/restrict/ai_accounts',
};

export async function probe(kind, fetcher = fetch) {
  try {
    const response = await fetcher(endpoints[kind], {
      signal: AbortSignal.timeout(15000), redirect: 'error',
    });
    const body = (await response.text()).slice(0, 8192);
    let data;
    try { data = JSON.parse(body); } catch {}
    const apiObject = data !== null && typeof data === 'object' && !Array.isArray(data);
    const reachable = kind === 'market'
      ? response.ok && apiObject && Number(data.retCode) === 0 && Number(data.result?.timeSecond) > 0
      : apiObject && ('retCode' in data || 'ret_code' in data || 'result' in data);
    const reason = reachable ? null
      : /block access from your country|country.*blocked|restricted.*region/i.test(body) ? 'region_restricted'
      : /access too frequent/i.test(body) ? 'rate_limit'
      : 'unknown';
    // An anonymous OAuth response only establishes reachability.
    // Do not expose upstream bodies or claim that an account is connected.
    return { reachable: Boolean(reachable), http_status: response.status, reason };
  } catch {
    return { reachable: false, http_status: null, reason: 'network' };
  }
}

const tokenPattern = /^[A-Za-z0-9_-]{43,128}$/;
const textValue = (value, max = 4096) => typeof value === 'string' && value.length > 0 && value.length <= max && !/\s/.test(value);
const exactKeys = (object, allowed) => Object.keys(object).every(key => allowed.includes(key));
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// The transport permits existing-account authorization and read-only API calls.
// It cannot create accounts, orders, transfers, withdrawals, or arbitrary targets.
export function validateRequest(input) {
  if (!plain(input) || !exactKeys(input, ['url', 'method', 'headers', 'body']) || typeof input.url !== 'string' || input.url.length > 8192) throw Error('invalid_request');
  const url = new URL(input.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash || !['api.bybit.com', 'api2.bybit.com'].includes(url.hostname)) throw Error('invalid_target');
  const method = input.method || 'GET';
  const query = url.searchParams;
  const matches = (expected, optional = []) => {
    const entries = [...query];
    return entries.length === new Set(entries.map(([key]) => key)).size && entries.every(([key, value]) => key in expected ? value === expected[key] : optional.includes(key)) && Object.entries(expected).every(([key, value]) => query.get(key) === value);
  };
  let signed = false, oauth = false, form = false;
  if (url.hostname === 'api.bybit.com' && method === 'GET') {
    if (url.pathname === '/v5/market/time' && matches({})) {}
    else if (url.pathname === '/v5/market/tickers' && matches({ category: 'spot' }, ['symbol']) && /^[A-Z0-9]{3,30}$/.test(query.get('symbol') || '')) {}
    else if (url.pathname === '/v5/account/wallet-balance' && matches({ accountType: 'UNIFIED' })) signed = true;
    else if (url.pathname === '/v5/position/list' && matches({ category: 'linear', settleCoin: 'USDT', limit: '50' })) signed = true;
    else if (url.pathname === '/v5/order/realtime' && matches({ category: 'spot', limit: '20' })) signed = true;
    else throw Error('invalid_target');
  } else if (url.hostname === 'api2.bybit.com') {
    if (method === 'GET' && url.pathname === '/oauth/v1/resource/restrict/ai_accounts' && matches({}, ['sub_member_id']) && (!query.has('sub_member_id') || /^\d{1,20}$/.test(query.get('sub_member_id')))) oauth = true;
    else if (method === 'POST' && ['/oauth/v1/public/access_token', '/oauth/v1/public/refresh_token'].includes(url.pathname) && matches({})) form = true;
    else throw Error('invalid_target');
  } else throw Error('invalid_target');
  const headers = {};
  if (input.headers !== undefined && !plain(input.headers)) throw Error('invalid_headers');
  for (const [rawKey, value] of Object.entries(input.headers || {})) {
    const key = rawKey.toLowerCase();
    if (key in headers || typeof value !== 'string' || value.length > 8192 || /[\r\n]/.test(value)) throw Error('invalid_headers');
    if (!(signed && ['x-bapi-api-key', 'x-bapi-sign', 'x-bapi-timestamp', 'x-bapi-recv-window'].includes(key)) && !(oauth && key === 'authorization') && !(form && key === 'content-type')) throw Error('invalid_headers');
    headers[key] = value;
  }
  if (signed && (!textValue(headers['x-bapi-api-key'], 256) || !/^[a-f0-9]{64}$/.test(headers['x-bapi-sign'] || '') || !/^\d{10,16}$/.test(headers['x-bapi-timestamp'] || '') || headers['x-bapi-recv-window'] !== '10000')) throw Error('invalid_headers');
  if (oauth && headers.authorization && !/^Bearer [^\s]{1,4096}$/.test(headers.authorization)) throw Error('invalid_headers');
  if (oauth && query.has('sub_member_id') && !headers.authorization) throw Error('invalid_headers');
  let body;
  if (form) {
    if (typeof input.body !== 'string' || input.body.length > 16384) throw Error('invalid_body');
    const params = new URLSearchParams(input.body);
    const expected = url.pathname.endsWith('/access_token') ? ['client_id', 'code', 'code_verifier'] : ['client_id', 'refresh_token'];
    if ([...params].length !== expected.length || !expected.every(key => params.getAll(key).length === 1) || params.get('client_id') !== 'ai-agent') throw Error('invalid_body');
    if (expected.includes('code') && (!textValue(params.get('code')) || !/^[A-Za-z0-9_-]{43,128}$/.test(params.get('code_verifier') || ''))) throw Error('invalid_body');
    if (expected.includes('refresh_token') && !textValue(params.get('refresh_token'))) throw Error('invalid_body');
    if (headers['content-type'] && !/^application\/x-www-form-urlencoded(?:;charset=UTF-8)?$/i.test(headers['content-type'])) throw Error('invalid_headers');
    headers['content-type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
    body = params.toString();
  } else if (input.body !== undefined && input.body !== null && input.body !== '') throw Error('invalid_body');
  return { url: url.toString(), options: { method, headers, ...(body === undefined ? {} : { body }), redirect: 'error', signal: AbortSignal.timeout(15000) } };
}

async function boundedBytes(stream, max) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream || []) {
    size += chunk.length;
    if (size > max) throw Error('size_limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

export function makeServer({ fetcher = fetch, now = Date.now, transportToken = process.env.BYBIT_TRANSPORT_TOKEN || '' } = {}) {
  let cached, expires = 0, pending;
  let active = 0;
  const check = () => {
    if (cached && now() < expires) return Promise.resolve(cached);
    if (pending) return pending;
    pending = Promise.all([probe('market', fetcher), probe('oauth', fetcher)])
      .then(([market, oauth]) => {
        cached = {
          checked_at: new Date(now()).toISOString(),
          market, oauth, account_connected: false,
          anonymous_check_only: true,
        };
        expires = now() + 60000;
        return cached;
      }).finally(() => { pending = undefined; });
    return pending;
  };
  return createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    const reply = (status, value) => { res.writeHead(status); res.end(JSON.stringify(value)); };
    if (req.url === '/request') {
      const fail = (status, code) => { req.resume(); res.setHeader('x-bybit-transport-error', code); return reply(status, { error: code }); };
      if (req.method !== 'POST') return fail(405, 'method_not_allowed');
      if (!tokenPattern.test(transportToken)) return fail(503, 'transport_not_configured');
      const supplied = req.headers.authorization;
      const expected = 'Bearer ' + transportToken;
      if (typeof supplied !== 'string' || Buffer.byteLength(supplied) !== Buffer.byteLength(expected) || !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) return fail(401, 'unauthorized');
      if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) return fail(415, 'unsupported_content_type');
      if (active >= 8) return fail(429, 'transport_busy');
      active++;
      try {
        let request;
        try { request = validateRequest(JSON.parse((await boundedBytes(req, 16384)).toString('utf8'))); }
        catch { return fail(400, 'invalid_request'); }
        let upstream, bytes;
        try { upstream = await fetcher(request.url, request.options); bytes = await boundedBytes(upstream.body, 1048576); }
        catch { return fail(502, 'upstream_unavailable'); }
        res.setHeader('content-type', (upstream.headers.get('content-type') || '').includes('application/json') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8');
        res.writeHead(upstream.status);
        res.end(bytes);
      } finally { active--; }
      return;
    }
    if (req.method !== 'GET') { req.resume(); return reply(405, { error: 'method_not_allowed' }); }
    // Exact paths: no input URL, account credentials, or arbitrary proxy targets.
    if (req.url === '/health') return reply(200, { server_ready: true, transport_ready: tokenPattern.test(transportToken), account_connected: false });
    if (req.url !== '/check') return reply(404, { error: 'not_found' });
    return reply(200, await check());
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = makeServer();
  server.requestTimeout = 20000;
  server.headersTimeout = 10000;
  server.listen(Number(process.env.PORT || 10000), '0.0.0.0');
}
