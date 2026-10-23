#!/usr/bin/env node
/** Phase 468. Seeded synthetic fixtures. Does not scrape advisories or copy bench apps. */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SYNTH';
const COMMENT = '// synthetic\n';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function xorshift(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

export function syntheticFiles(seed) {
  const next = xorshift(seed);
  const n = next() % 1000;
  const source = `${COMMENT}function source${n}(req) {\n  return req.query.q;\n}\n`;
  const sink = `${COMMENT}function sink${n}(value) {\n  return value;\n}\n`;
  const sanitizer = `${COMMENT}function sanitizer${n}(value) {\n  return String(value);\n}\n`;
  return [
    { name: 'source.js', body: source, synthetic: true },
    { name: 'sink.js', body: sink, synthetic: true },
    { name: 'sanitizer.js', body: sanitizer, synthetic: true },
  ];
}

export function assertNotGroundTruth(filePath) {
  const normalized = filePath.replaceAll('\\', '/');
  if (normalized.includes('/synthetic/') || normalized.endsWith('/synthetic')) {
    throw new Error('ground truth refuses synthetic fixtures');
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const seedText = arg(argv, '--seed');
  const out = arg(argv, '--out');
  if (seedText === undefined || out === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --seed <n> --out <dir>\n' };
  }
  if (out.replaceAll('\\', '/').includes('/bench/')) {
    return { code: 1, stdout: '', stderr: 'synthetic fixtures stay out of bench/\n' };
  }
  const seed = Number(seedText);
  if (!Number.isInteger(seed)) return { code: 2, stdout: '', stderr: 'seed must be an integer\n' };
  mkdirSync(out, { recursive: true });
  const files = syntheticFiles(seed);
  for (const file of files) writeFileSync(join(out, file.name), file.body);
  return { code: 0, stdout: files.map((file) => file.name).join('\n') + '\n', stderr: '' };
}

function isDirect() {
  const entry = process.argv[1];
  return entry !== undefined && fileURLToPath(import.meta.url) === entry;
}

if (isDirect()) {
  const result = main();
  if (result.stdout !== '') process.stdout.write(result.stdout);
  if (result.stderr !== '') process.stderr.write(result.stderr);
  process.exit(result.code);
}
