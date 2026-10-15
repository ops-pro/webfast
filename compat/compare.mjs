// Differential check: sends the same requests to Caddy and to webfast (same Caddyfile, same site)
// and reports every difference in status, headers and (decoded) body.
//   node compare.mjs http://caddy:8080 http://ours:8080
// Expected differences are listed, not failed: ETag values (ours hash the content), Last-Modified
// (ours have none), Via on proxied responses (Caddy adds one), and the compressed bytes of on-the-fly
// encoding (different compressors; the decoded bodies must match).
import http from 'node:http';
import zlib from 'node:zlib';

const [caddyBase, oursBase] = process.argv.slice(2);
if (!caddyBase || !oursBase) {
  console.error('usage: node compare.mjs <caddy-base-url> <ours-base-url>');
  process.exit(2);
}

const BROWSER = 'gzip, deflate, br, zstd';
const cases = [
  ['GET', '/healthz'],
  ['GET', '/_internal/notes.txt'],
  ['GET', '/.git/config'],
  ['GET', '/.env'],
  ['GET', '/en/../.env'],
  ['GET', '//en/'],
  ['GET', '/en/'],
  ['GET', '/en/', { 'accept-encoding': BROWSER }],
  ['GET', '/en/', { 'accept-encoding': 'gzip' }],
  ['GET', '/en/', { 'accept-encoding': 'zstd' }],
  ['GET', '/en/', { 'accept-encoding': 'br;q=0.5, gzip;q=0.8' }],
  ['GET', '/en/', { 'accept-encoding': 'identity' }],
  ['GET', '/en/', { 'accept-encoding': '*' }],
  ['GET', '/en'],
  ['GET', '/en?a=1'],
  ['GET', '/en/contact'],
  ['GET', '/en/contact.html'],
  ['GET', '/en/contact.html?x=1'],
  ['GET', '/en/contact/'],
  ['GET', '/en/%63ontact'],
  ['GET', '/en/index.html'],
  ['GET', '/en/index'],
  ['GET', '/en/services'],
  ['GET', '/en/services/'],
  ['GET', '/en/services/overview', { 'accept-encoding': BROWSER }],
  ['GET', '/de/pricing'],
  ['GET', '/fr/', { 'accept-encoding': BROWSER }],
  ['GET', '/ru/about', { 'accept-encoding': BROWSER }],
  ['GET', '/EN/'],
  ['GET', '/En/contact'],
  ['GET', '/assets/main-Sample.css', { 'accept-encoding': BROWSER }],
  ['GET', '/assets/form-Sample.js'],
  ['GET', '/fonts/sans-latin.woff2'],
  ['GET', '/images/logo.svg', { 'accept-encoding': BROWSER }],
  ['GET', '/images/hero.webp'],
  ['GET', '/favicon.svg'],
  ['GET', '/favicon.ico'],
  ['GET', '/site.webmanifest'],
  ['GET', '/sw.js'],
  ['GET', '/v.json', { 'accept-encoding': BROWSER }],
  ['GET', '/llms.txt', { 'accept-encoding': BROWSER }],
  ['HEAD', '/en/'],
  ['HEAD', '/en/', { 'accept-encoding': BROWSER }],
  ['POST', '/en/'],
  ['OPTIONS', '/en/contact'],
  ['DELETE', '/assets/form-Sample.js'],
  ['GET', '/en/', { 'if-none-match': '*' }],
  ['GET', '/en/', { 'if-match': '"nope"' }],
  ['GET', '/en/contact', { range: 'bytes=0-99' }],
  ['GET', '/en/contact', { range: 'bytes=-50' }],
  ['GET', '/en/contact', { range: 'bytes=999999-' }],
  ['GET', '/en/contact', { range: 'bytes=0-1,5-6' }],
  ['GET', '/en/contact', { range: 'bytes=0-99', 'accept-encoding': 'br' }],
  ['GET', '/'],
  ['GET', '/', { 'accept-encoding': BROWSER }],
  ['GET', '/robots.txt'],
  ['GET', '/sitemap.xml'],
  ['GET', '/pricing?ref=x'],
  ['GET', '/nonexistent.png'],
  ['GET', '/missing-page'],
  ['GET', '/api/health'],
  ['GET', '/api/forms/x', { 'accept-encoding': BROWSER }],
  ['GET', '/api/forms/x', { 'accept-encoding': 'gzip' }],
  ['GET', '/api/forms/x', { 'x-forwarded-for': '203.0.113.7', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'example.com' }],
  ['GET', '/api/forms/x', { connection: 'X-Secret', 'x-secret': '1' }],
  ['POST', '/api/forms/submit', { 'content-type': 'application/json' }, '{"name":"test"}'],
  ['GET', '/api/stream/chat', { 'accept-encoding': BROWSER }],
  ['GET', '/api/stream/quota'],
  ['GET', '/stream'],
  ['GET', '/stream/card'],
  ['GET', '/missing'],
];

function request(base, method, path, headers = {}, body) {
  const url = new URL(base);
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const req = http.request(
      { host: url.hostname, port: url.port, method, path, headers: { ...headers }, agent: false },
      (res) => {
        const chunks = [];
        let first = null;
        res.on('data', (c) => {
          if (first === null) first = performance.now() - started;
          chunks.push(c);
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headersDistinct,
            body: Buffer.concat(chunks),
            first,
            total: performance.now() - started,
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function decode(res) {
  const enc = res.headers['content-encoding']?.[0];
  try {
    if (enc === 'br') return zlib.brotliDecompressSync(res.body);
    if (enc === 'gzip') return zlib.gunzipSync(res.body);
    if (enc === 'zstd') return zlib.zstdDecompressSync(res.body);
  } catch (e) {
    return Buffer.from(`<undecodable ${enc}: ${e.message}>`);
  }
  return res.body;
}

/** Proxied JSON echoes differ only in each proxy's host name and peer address; multipart range
 * responses only in their random boundary. Caddy's transport also asks the upstream for gzip when
 * the client sent no Accept-Encoding (and unpacks it); ours forwards the client's header as is. */
function normalizeBody(text, clientAcceptEncoding) {
  text = text.replace(/compat-(caddy|ours):8080/g, '<host>').replace(/--[0-9a-f]{60}/g, '--<boundary>');
  try {
    const json = JSON.parse(text);
    if (json && json.service && json.headers) {
      for (const field of ['x-forwarded-for']) {
        if (json.headers[field]) json.headers[field] = json.headers[field].replace(/172\.\d+\.\d+\.\d+/g, '<proxy-peer>');
      }
      if (!clientAcceptEncoding && json.headers['accept-encoding'] === 'gzip') delete json.headers['accept-encoding'];
      return JSON.stringify(json);
    }
  } catch {
    /* not JSON */
  }
  return text;
}

const KNOWN = new Set(['date', 'etag', 'last-modified', 'via']);
// Caddy skips deferred `header` operations (here: the site's security headers and `-Server`) when a
// handler returns an error such as file_server's 405; webfast keeps them.
const DEFERRED_ON_ERRORS = new Set([
  'content-security-policy',
  'cross-origin-opener-policy',
  'permissions-policy',
  'referrer-policy',
  'server',
  'strict-transport-security',
  'x-content-type-options',
  'x-dns-prefetch-control',
  'x-frame-options',
]);

let failures = 0;
const known = new Map();
for (const [method, path, headers, body] of cases) {
  const [a, b] = await Promise.all([
    request(caddyBase, method, path, headers, body),
    request(oursBase, method, path, headers, body),
  ]);
  const diffs = [];
  if (a.status !== b.status) diffs.push(`status ${a.status} vs ${b.status}`);
  const names = new Set([...Object.keys(a.headers), ...Object.keys(b.headers)]);
  const onTheFly = (r) => r.headers['content-encoding'] && r.headers['x-upstream'];
  const clientAe = headers?.['accept-encoding'];
  const da = normalizeBody(decode(a).toString('latin1'), clientAe);
  const db = normalizeBody(decode(b).toString('latin1'), clientAe);
  const sameBody = da === db;
  for (const name of [...names].sort()) {
    const norm = (v) => v.replace(/boundary=[0-9a-f]{60}/, 'boundary=<b>');
    const va = norm((a.headers[name] ?? []).join(' | '));
    const vb = norm((b.headers[name] ?? []).join(' | '));
    if (va === vb) continue;
    if (a.status === 405 && b.status === 405 && DEFERRED_ON_ERRORS.has(name)) {
      known.set(
        '405: site headers on handler errors (ours keep them)',
        (known.get('405: site headers on handler errors (ours keep them)') ?? 0) + 1,
      );
      continue;
    }
    if (name === 'content-length' && sameBody && !a.headers['content-encoding']) {
      if (a.headers['x-upstream'] && !clientAe)
        known.set(
          'upstream Accept-Encoding (Caddy asks for gzip)',
          (known.get('upstream Accept-Encoding (Caddy asks for gzip)') ?? 0) + 1,
        );
      continue;
    }
    if (KNOWN.has(name)) {
      const kind =
        name === 'etag'
          ? Boolean(va) === Boolean(vb)
            ? 'etag values'
            : 'etag presence'
          : `${name} (${va ? 'caddy' : ''}${vb ? 'ours' : ''})`;
      if (kind === 'etag presence') diffs.push(`etag: caddy=${va || '-'} ours=${vb || '-'}`);
      else known.set(kind, (known.get(kind) ?? 0) + 1);
      continue;
    }
    if (name === 'content-length' && (onTheFly(a) || onTheFly(b))) continue;
    diffs.push(`${name}: caddy=${va || '-'} ours=${vb || '-'}`);
  }
  if (!sameBody)
    diffs.push(
      `body differs (${da.length} vs ${db.length} bytes): caddy=${JSON.stringify(da.slice(0, 160))} ours=${JSON.stringify(db.slice(0, 160))}`,
    );
  if (path === '/api/stream/chat') {
    for (const [who, r] of [
      ['caddy', a],
      ['ours', b],
    ]) {
      if (!(r.first < 250 && r.total >= 390))
        diffs.push(`${who}: SSE not streamed (first ${r.first?.toFixed(0)} ms, total ${r.total.toFixed(0)} ms)`);
    }
  }
  const label = `${method} ${path}${headers ? ' ' + JSON.stringify(headers) : ''}`;
  if (diffs.length) {
    failures += 1;
    console.log(`DIFF ${label}\n  ${diffs.join('\n  ')}`);
  } else {
    console.log(`ok   ${label} → ${a.status}`);
  }
}

// Conditional requests with each server's own validator.
for (const [path, enc] of [
  ['/en/', undefined],
  ['/en/', 'br'],
  ['/assets/main-Sample.css', BROWSER],
]) {
  const headers = enc ? { 'accept-encoding': enc } : {};
  for (const [who, base] of [
    ['caddy', caddyBase],
    ['ours', oursBase],
  ]) {
    const first = await request(base, 'GET', path, headers);
    const etag = first.headers.etag?.[0];
    const again = await request(base, 'GET', path, { ...headers, 'if-none-match': etag });
    const ok = etag && again.status === 304 && again.body.length === 0 && again.headers.etag?.[0] === etag;
    if (!ok) failures += 1;
    console.log(`${ok ? 'ok  ' : 'DIFF'} ${who} If-None-Match ${path} ${enc ?? ''} → ${again.status}`);
  }
}

console.log('\nexpected differences:');
for (const [kind, count] of known) console.log(`  ${kind}: ${count} response(s)`);
console.log(failures ? `\n${failures} case(s) differ` : '\nall cases match');
process.exit(failures ? 1 : 0);
