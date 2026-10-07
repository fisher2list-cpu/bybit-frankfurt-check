import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

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

export function makeServer({ fetcher = fetch, now = Date.now } = {}) {
  let cached, expires = 0, pending;
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
    if (req.method !== 'GET') { req.resume(); return reply(405, { error: 'method_not_allowed' }); }
    // Exact paths: no input URL, account credentials, or arbitrary proxy targets.
    if (req.url === '/health') return reply(200, { server_ready: true, account_connected: false });
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
