#!/usr/bin/env node
/**
 * Runtime overhead benchmark (SECURITY_SCANNER_SPEC.md §4.5 / §9 Phase 8).
 * Measures p95 added latency of inspect() on a typical JSON request.
 * Fails if p95 >= 1ms.
 */
import { createInspector } from '../dist/runtime/index.js';

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
console.log('bench: p95 < 1ms');
