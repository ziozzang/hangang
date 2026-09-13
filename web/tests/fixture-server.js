import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
// Match src/ui.rs: fresh HTML style nonce, same-origin scripts, no unsafe-inline/eval.
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (url.pathname === '/ui/' || url.pathname === '/ui/index.html') return file(response, 'index.html');
  if (url.pathname === '/ui/lua-editor.js') return file(response, 'lua-editor.js');
  if (url.pathname === '/ui/lua-editor.css') return file(response, 'lua-editor.css');
  if (url.pathname === '/ui/app.js') return file(response, 'app.js');
  if (url.pathname === '/ui/console.js') return file(response, 'console.js');
  if (url.pathname === '/ui/operations.js') return file(response, 'operations.js');
  if (url.pathname === '/ui/docker.js') return file(response, 'docker.js');
  if (url.pathname === '/ui/i18n.js') return file(response, 'i18n.js');
  for (const name of ['ko-static.js', 'ko-app.js', 'ko-console.js', 'ko-operations.js', 'ko-docker.js']) {
    if (url.pathname === `/ui/locales/${name}`) return file(response, path.join('locales', name));
  }
  if (url.pathname === '/ui/style.css') return file(response, 'style.css');
  response.writeHead(404); response.end('fixture route missing');
});
async function file(response, name) {
  let data = await readFile(path.join(root, name));
  const nonce = name === 'index.html' ? randomBytes(32).toString('base64') : null;
  if (nonce) data = Buffer.from(data.toString('utf8').replace('<head>', `<head><meta name="csp-nonce" content="${nonce}">`));
  const styles = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  response.writeHead(200, { 'content-type': types[path.extname(name)], 'cache-control': 'no-store',
    'content-security-policy': `default-src 'none'; script-src 'self'; style-src ${styles}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` });
  response.end(data);
}

server.listen(41739, '127.0.0.1');
