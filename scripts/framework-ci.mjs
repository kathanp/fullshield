#!/usr/bin/env node
// Scans the Next, Nest, and Fastify fixture apps with the built CLI.
// The six-job verify matrix runs this after npm run verify, which builds dist.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(root, 'dist', 'cli', 'index.js');

if (!existsSync(cli)) {
  console.error('framework-ci: dist/cli/index.js is missing. Run npm run build first.');
  process.exit(1);
}

const cases = [
  ['test/fixtures/frameworks/nest-vuln', 'SAST-NEST-001', true],
  ['test/fixtures/frameworks/nest-clean', 'SAST-NEST-001', false],
  ['test/fixtures/frameworks/next-vuln', 'SAST-NEXT-ROUTE-001', true],
  ['test/fixtures/frameworks/next-clean', 'SAST-NEXT-ROUTE-001', false],
  ['test/fixtures/frameworks/fastify-vuln', 'SAST-FASTIFY-001', true],
  ['test/fixtures/frameworks/fastify-clean', 'SAST-FASTIFY-001', false],
];

function ruleIds(dir) {
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--offline'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0 && result.status !== 1) {
    console.error(result.stderr);
    throw new Error(`framework-ci: scan ${dir} exited ${result.status}`);
  }
  const report = JSON.parse(result.stdout);
  const findings = Array.isArray(report.findings) ? report.findings : [];
  return findings.map((row) => row.ruleId);
}

let failed = false;
for (const [dir, ruleId, want] of cases) {
  const ids = ruleIds(dir);
  const hit = ids.includes(ruleId);
  if (hit !== want) {
    failed = true;
    console.error(`${dir}: expected ${ruleId} ${want ? 'present' : 'absent'}`);
  } else {
    console.log(`${want ? 'found' : 'clean'} ${ruleId} ${dir}`);
  }
}

if (failed) {process.exit(1);}
