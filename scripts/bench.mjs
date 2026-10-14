#!/usr/bin/env node
/**
 * Runtime overhead benchmark (SECURITY_SCANNER_SPEC.md §4.5 / §9 Phase 8).
 * 1. inspect() p95 on a typical JSON request — fail if p95 >= 1ms.
 * 2. Full Express request p50/p95 with shieldGuard on the stack (informational).
 */
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { request as httpRequest } from 'node:http';

import { createInspector } from '../dist/runtime/index.js';
import { shieldGuard } from '../dist/runtime/express.js';

const require = createRequire(import.meta.url);

const inspect = createInspector({ mode: 'monitor' });
const req = {
  path: '/api/items',
  method: 'POST',
  ip: '203.0.113.10',
  query: { page: '1' },
  body: { name: 'widget', qty: 2, tags: ['a', 'b'] },
  params: { id: '42' },
};

const WARM = 200;
const N = 4000;
for (let i = 0; i < WARM; i += 1) inspect(req);

const samples = new Float64Array(N);
for (let i = 0; i < N; i += 1) {
  const t0 = performance.now();
  inspect(req);
  samples[i] = performance.now() - t0;
}
samples.sort();
const p50 = samples[Math.floor(N * 0.5)];
const p95 = samples[Math.floor(N * 0.95)];
const p99 = samples[Math.floor(N * 0.99)];
console.log(`bench inspect() n=${N} p50=${p50.toFixed(4)}ms p95=${p95.toFixed(4)}ms p99=${p99.toFixed(4)}ms`);
if (p95 >= 1) {
  console.error(`VERIFY FAILED: runtime p95 ${p95.toFixed(4)}ms >= 1ms`);
  process.exit(1);
}
console.log('bench: inspect() p95 < 1ms');

await benchExpress();

async function benchExpress() {
  let express;
  try {
    express = require('express');
  } catch {
    console.log('bench express: skipped (express not installed)');
    return;
  }

  const app = express();
  // fullshield-ignore CONFIG-HELMET-001: loopback bench harness, not a server
  // fullshield-ignore CONFIG-BODYLIMIT-001: loopback bench harness, not a server
  app.use(express.json());
  app.use(shieldGuard({ mode: 'monitor' }));
  app.post('/api/items', (_req, res) => {
    res.json({ ok: true });
  });

  const server = createServer(app);
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  const body = JSON.stringify({ name: 'widget', qty: 2, tags: ['a', 'b'] });

  const post = () =>
    new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: '127.0.0.1',
          port,
          path: '/api/items',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume();
          res.on('end', resolve);
        },
      );
      r.on('error', reject);
      r.write(body);
      r.end();
    });

  const EXPRESS_WARM = 50;
  const EXPRESS_N = 400;
  for (let i = 0; i < EXPRESS_WARM; i += 1) await post();

  const expressSamples = new Float64Array(EXPRESS_N);
  for (let i = 0; i < EXPRESS_N; i += 1) {
    const t0 = performance.now();
    await post();
    expressSamples[i] = performance.now() - t0;
  }
  expressSamples.sort();
  const e50 = expressSamples[Math.floor(EXPRESS_N * 0.5)];
  const e95 = expressSamples[Math.floor(EXPRESS_N * 0.95)];
  console.log(
    `bench express+shieldGuard n=${EXPRESS_N} p50=${e50.toFixed(3)}ms p95=${e95.toFixed(3)}ms`,
  );

  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}
