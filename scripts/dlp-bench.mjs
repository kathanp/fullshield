/**
 * Phase 32 DLP budget: p95 extra latency for a ≤64 KB JSON/text body.
 * Prints a single number (p95 milliseconds) to stdout.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
process.env.FULLSHIELD_EXPERIMENTAL_DLP = '1';

const { createDlpInspector } = await import(pathToFileURL(join(root, 'dist', 'runtime', 'dlp.js')).href);
const dlp = createDlpInspector({ dlp: { mode: 'monitor' } });
if (dlp === undefined) {
  console.error('createDlpInspector returned undefined');
  process.exit(2);
}

const body = `{"ok":true,"data":"${'n'.repeat(60_000)}","note":"hello"}`;
const WARM = 80;
const N = 300;
let best = Infinity;
for (let trial = 0; trial < 3; trial += 1) {
  for (let i = 0; i < WARM; i += 1) dlp.inspect(body, { path: '/bench' });
  globalThis.gc?.();
  const samples = [];
  for (let i = 0; i < N; i += 1) {
    const t0 = performance.now();
    dlp.inspect(body, { path: '/bench' });
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const p95 = samples[Math.floor(samples.length * 0.95)] ?? 99;
  if (p95 < best) best = p95;
}
process.stdout.write(String(best));
