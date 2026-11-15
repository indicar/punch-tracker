// Punch tracker — keet-style: «сервер сам говорит клиенту, как он выглядит снаружи»
// + живая сигнальная почта (мгновенная, без лимитов gist/TG).
// Развёртывание: Render web service (Node, без зависимостей).
const http = require('http');

const store = {}; // role -> { line, ts, seen_ip, seen_port }
const mbox = {};  // role -> [{from, text, t}] — релей-фолбэк, когда UDP не пробит
const logs = {};  // role -> [{seq, t, text}] — журнал клиентов, читаемо удалённо
let logSeq = 0;
const files = {}; // role -> [{id,name,from,t,size,buf}] — HTTP-релей файлов (in-memory: free-диск эфемерный)
let fileSeq = 0;
const FILE_CAP = 30 * 1024 * 1024;   // один файл
const MEM_CAP = 200 * 1024 * 1024;   // суммарно в памяти (free-инстанс: 512 MB)
const FILES_TTL = 3600e3;            // час жизни неотобранного

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
  // релей-фолбэк (keet-style): POST /msg/<role>?from=<роль> телом — текст; GET /msg/<role> — забрать и очистить
  if (req.method === 'POST' && p.startsWith('/msg/')) {
    const role = p.slice(5).replace(/[^a-z]/g, '');
    let body = '';
    req.on('data', c => { body += c; if (body.length > 8192) req.destroy(); });
    req.on('end', () => {
      if (!body.trim()) return send(400, { ok: false, err: 'empty' });
      const q = mbox[role] = mbox[role] || [];
      q.push({ from: (u.searchParams.get('from') || '').replace(/[^a-z]/g, ''), text: body.slice(0, 4000), t: Date.now() });
      if (q.length > 100) q.splice(0, q.length - 100);
      send(200, { ok: true, n: q.length });
    });
    return;
  }
  if (p.startsWith('/msg/')) {
    const q = mbox[p.slice(5)] || [];
    return send(200, { ok: true, msgs: q.splice(0, q.length) });
  }
  if (p === '/lines') return send(200, { ok: true, ...store });

  // ---- файлы: POST /file/<role>?from=..&name=.. телом — байты;
  //      GET /files/<role> — список; GET /dl/<role>/<id> — скачать (удаляется после выдачи)
  if (req.method === 'POST' && p.startsWith('/file/')) {
    const role = p.slice(6).replace(/[^a-z]/g, '');
    const chunks = []; let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > FILE_CAP) { res.writeHead(413, { 'access-control-allow-origin': '*' }); res.end('too big'); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (res.writableEnded) return;
      const buf = Buffer.concat(chunks);
      if (!buf.length) return send(400, { ok: false, err: 'empty' });
      const q = files[role] = files[role] || [];
      const now = Date.now();
      while (q.length && (now - q[0].t > FILES_TTL || q.reduce((s, f) => s + f.size, 0) + buf.length > MEM_CAP)) q.shift().buf = null;
      const f = { id: ++fileSeq, name: (u.searchParams.get('name') || 'file').slice(0, 200), from: (u.searchParams.get('from') || '').replace(/[^a-z]/g, ''), t: now, size: buf.length, buf };
      q.push(f);
      send(200, { ok: true, id: f.id, size: f.size });
    });
    return;
  }
  if (p.startsWith('/files/')) {
    const q = files[p.slice(7).replace(/[^a-z]/g, '')] || [];
    return send(200, { ok: true, files: q.map(f => ({ id: f.id, name: f.name, size: f.size, from: f.from, t: f.t })) });
  }
  if (p.startsWith('/dl/')) {
    const m = p.slice(4).match(/^([a-z]+)\/(\d+)$/);
    if (!m) return send(400, { ok: false, err: 'bad dl' });
    const q = files[m[1]] || [];
    const i = q.findIndex(f => f.id === parseInt(m[2], 10));
    if (i < 0) return send(404, { ok: false, err: 'gone' });
    const f = q.splice(i, 1)[0];
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': f.size,
      'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`,
      'access-control-allow-origin': '*' });
    return res.end(f.buf);
  }

  // журнал: POST /log/<role> телом — строки (могут быть \\n); GET /logs/<role>?since=<seq>&limit=
  if (req.method === 'POST' && p.startsWith('/log/')) {
    const role = p.slice(5).replace(/[^a-z]/g, '');
    let body = '';
    req.on('data', c => { body += c; if (body.length > 8192) req.destroy(); });
    req.on('end', () => {
      const arr = logs[role] = logs[role] || [];
      for (const line of body.split('\n')) {
        if (line.trim()) arr.push({ seq: ++logSeq, t: Date.now(), text: line.slice(0, 500) });
      }
      if (arr.length > 800) arr.splice(0, arr.length - 800);
      send(200, { ok: true, n: arr.length });
    });
    return;
  }
  if (p.startsWith('/logs/')) {
    const role = p.slice(6).replace(/[^a-z]/g, '');
    const since = parseInt(u.searchParams.get('since') || '0', 10) || 0;
    const limit = parseInt(u.searchParams.get('limit') || '400', 10) || 400;
    const arr = (logs[role] || []).filter(l => l.seq > since).slice(-limit);
    return send(200, { ok: true, lines: arr });
  }
  send(404, { ok: false, err: 'no route' });
});

server.listen(process.env.PORT || 10099, () => console.log('punch-tracker up'));
