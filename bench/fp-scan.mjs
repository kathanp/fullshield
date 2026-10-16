#!/usr/bin/env node
/**
 * Scan one pinned real-world repo. Does not invent a precision number.
 * Refuses to run unless the checkout exists at the pinned SHA.
 *
 *   node bench/fp-scan.mjs --repo express
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const registry = JSON.parse(readFileSync(join(root, 'bench', 'realworld.json'), 'utf8'));

function arg(name) {
  const idx = process.argv.indexOf(name);
  return idx === -1 ? '' : (process.argv[idx + 1] ?? '');
}

const name = arg('--repo');
const repo = registry.repos.find((item) => item.name === name);
if (repo === undefined) {
  console.error('pass --repo with a name from bench/realworld.json');
  process.exit(2);
}
const dest = join(process.env.FULLSHIELD_BENCH_DIR || join(homedir(), 'fullshield-bench'), name);
if (!existsSync(join(dest, 'package.json'))) {
  console.error(`${name} is not checked out at ${dest}. This script does not clone or invent findings.`);
  process.exit(1);
}
const sha = spawnSync('git', ['-C', dest, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
if (sha.stdout.trim() !== repo.sha) {
  console.error(`${name} HEAD is ${sha.stdout.trim()} ; registry pins ${repo.sha}`);
  process.exit(1);
}
const cli = join(root, 'dist', 'cli', 'index.js');
if (!existsSync(cli)) {
  console.error('dist/cli/index.js is missing. Run npm run build first.');
  process.exit(1);
}
const flags = ['', 'FULLSHIELD_EXPERIMENTAL_TAINT_V2'];
for (const flag of flags) {
  const env = { ...process.env };
  if (flag !== '') env[flag] = '1';
  const result = spawnSync(process.execPath, [cli, 'scan', dest, '--json', '--offline-safe'], {
    cwd: root,
    encoding: 'utf8',
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  const label = flag === '' ? 'default' : flag;
  const out = join(root, 'bench', 'fp', name, `${label}.json`);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, result.stdout);
  console.log(`wrote ${out} (exit ${result.status})`);
}
console.log('Precision is unsampled until a human labels these findings. No rate is computed here.');
