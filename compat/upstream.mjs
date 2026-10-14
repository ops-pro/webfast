// Stub upstream for the compatibility check: echoes the request (as the app or the streaming service would see it)
// and streams SSE on /api/stream/chat. Run as `app` (PORT 8787) and `stream` (PORT 8800).
import http from 'node:http';

const port = Number(process.env.PORT ?? 8787);
const name = process.env.NAME ?? 'app';
const seen = [
  'host',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'accept-encoding',
  'content-length',
  'transfer-encoding',
  'connection',
  'te',
  'if-none-match',
  'x-secret',
];

http
  .createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (req.url.startsWith('/api/stream/chat')) {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
        res.write('data: 1\n\n');
        setTimeout(() => res.end('data: 2\n\n'), 400);
        return;
      }
      const headers = Object.fromEntries(seen.filter((h) => h in req.headers).map((h) => [h, req.headers[h]]));
      const body = JSON.stringify({
        service: name,
        method: req.method,
        url: req.url,
        headers,
        bodyBytes: Buffer.concat(chunks).length,
        padding: 'x'.repeat(600),
      });
      const status = req.url.startsWith('/missing') ? 404 : 200;
      res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'",
        'x-upstream': name,
        connection: 'keep-alive, X-Hop',
        'x-hop': 'dropped',
      });
      res.end(body);
    });
  })
  .listen(port, '0.0.0.0', () => console.log(`${name} listening on ${port}`));
