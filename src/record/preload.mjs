import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, join } from 'node:path';

const target = process.env.FULLSHIELD_EVIDENCE ?? join(process.cwd(), '.fullshield', 'evidence.json');
const files = new Set();
const routes = new Set();
if (typeof process.argv[1] === 'string' && process.argv[1].length > 0) {
  files.add(process.argv[1]);
}

function flush() {
  mkdirSync(dirname(target), { recursive: true });
  let prev = { files: [], routes: [] };
  try {
    const parsed = JSON.parse(readFileSync(target, 'utf8'));
    if (Array.isArray(parsed.files)) {prev.files = parsed.files;}
    if (Array.isArray(parsed.routes)) {prev.routes = parsed.routes;}
  } catch {
    prev = { files: [], routes: [] };
  }
  const body = {
    files: [...new Set([...prev.files, ...files])],
    routes: [...new Set([...prev.routes, ...routes])],
  };
  writeFileSync(target, `${JSON.stringify(body, null, 2)}\n`);
}

const createServer = http.createServer;
http.createServer = function createRecordedServer(...args) {
  const server = createServer.apply(this, args);
  server.on('request', (req) => {
    const path = (req.url ?? '/').split('?')[0];
    routes.add(`${req.method ?? 'GET'} ${path}`);
    flush();
  });
  return server;
};

flush();
