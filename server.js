// Punch tracker — keet-style: «сервер сам говорит клиенту, как он выглядит снаружи»
// + живая сигнальная почта (мгновенная, без лимитов gist/TG).
// Развёртывание: Render web service (Node, без зависимостей).
const http = require('http');

const store = {}; // role -> { line, ts, seen_ip, seen_port }

// Что видно о соединении: Render ставит X-Forwarded-For (цепочка IP), порт — к сожалению,
// только если фронт его пробрасывает. Пробуем заголовок, потом сокет.
function observed(req) {
  const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = xff || req.socket.remoteAddress || '';
  let port = 0;
  const xp = req.headers['x-forwarded-client-port'] || req.headers['x-real-port'] || req.headers['cf-connecting-port'];
  if (xp) port = parseInt(xp, 10) || 0;
  if (!port) port = req.socket.remotePort || 0; // за Render это порт прокси — проверим живьём
  return { ip: clean(ip), port };
}
function clean(ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;
  const send = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(JSON.stringify(obj));
  };
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST', 'access-control-allow-headers': 'content-type' }); return res.end(); }
  const obs = observed(req);

  if (p === '/' ) return send(200, { ok: true, svc: 'punch-tracker', t: Date.now() });

  // keet-наблюдение: как сервер видит этот запрос
  if (p === '/obs') return send(200, { ip: obs.ip, port: obs.port, t: Date.now() });

  // почта: POST /line/<role>?lan=..&alt=..  телом "ip port nonce ts"
  if (req.method === 'POST' && p.startsWith('/line/')) {
    const role = p.slice(6).replace(/[^a-z]/g, '');
    let body = '';
    req.on('data', c => { body += c; if (body.length > 512) req.destroy(); });
    req.on('end', () => {
      const parts = body.trim().split(/\s+/);
      if (parts.length >= 2 && /^\d+\.\d+\.\d+\.\d+$/.test(parts[0])) {
        store[role] = {
          ip: parts[0], port: parseInt(parts[1], 10) || 0,
          nonce: parts[2] || '', ts: parseInt(parts[3], 10) || 0,
          lan: u.searchParams.get('lan') || '', alt: u.searchParams.get('alt') || '',
          seen_ip: obs.ip, seen_port: obs.port, seen_t: Date.now()
        };
        return send(200, { ok: true, you: obs });
      }
      send(400, { ok: false, err: 'bad line' });
    });
    return;
  }
  // GET /line/<role> — строка пира + как сервер видел его последний раз
  if (p.startsWith('/line/')) {
    const role = p.slice(6);
    const s = store[role];
    if (!s) return send(404, { ok: false });
    return send(200, { ok: true, role, ...s });
  }
  if (p === '/lines') return send(200, { ok: true, ...store });

  send(404, { ok: false, err: 'no route' });
});

server.listen(process.env.PORT || 10099, () => console.log('punch-tracker up'));
