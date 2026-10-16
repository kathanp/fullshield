#!/usr/bin/env node
/**
 * Performance harness. Writes a measurement only after a real run.
 * With no checkout, it records that the targets were not measured.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const baselinePath = join(root, 'bench', 'perf-baseline.json');
const home = process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench');
const wanted = ['next', 'nest', 'undici'];
const present = wanted.filter((name) => existsSync(join(home, name, 'package.json')));

if (present.length < wanted.length) {
  const doc = {
    measured: false,
    reason: 'next, nest, and undici are not all checked out. No timing or memory number is recorded.',
    targets: {
      coldSeconds: 60,
      warmSeconds: 20,
      incrementalSeconds: 5,
      peakMemoryMb: 1536,
    },
  };
  writeFileSync(baselinePath, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(doc.reason);
  process.exit(0);
}

const previous = existsSync(baselinePath) ? JSON.parse(readFileSync(baselinePath, 'utf8')) : null;
if (previous !== null && previous.measured === true && Array.isArray(previous.p50Ms)) {
  console.log('baseline present; a regression check needs three new runs, which this invocation does not start.');
}
console.log(`checkouts present: ${present.join(', ')}. Run the CLI three times and store p50 before treating a regression as measured.`);
