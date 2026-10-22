#!/usr/bin/env node
/** Phase 489. Propose holdout rotation. Reads the registry and does not write it. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOLDOUTROT';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function proposal(doc) {
  const apps = Array.isArray(doc.apps) ? doc.apps : [];
  const seen = apps.filter((app) => app.status === 'seen').map((app) => app.name);
  const untouched = apps.filter((app) => app.status === 'untouched').map((app) => app.name);
  const lines = [
    'holdout rotation proposal',
    `seen that could leave: ${seen.join(', ')}`,
    `untouched reserves: ${untouched.join(', ')}`,
  ];
  return { text: lines.join('\n'), reserves: untouched.length };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const registry = arg(argv, '--registry');
  if (registry === undefined) return { code: 2, stdout: '', stderr: 'usage: --registry <file>\n' };
  const before = createHash('sha256').update(readFileSync(registry)).digest('hex');
  const doc = JSON.parse(readFileSync(registry, 'utf8'));
  const { text, reserves } = proposal(doc);
  const after = createHash('sha256').update(readFileSync(registry)).digest('hex');
  if (before !== after) return { code: 1, stdout: '', stderr: 'registry hash changed\n' };
  if (reserves < 2) return { code: 1, stdout: `${text}\n`, stderr: 'fewer than two untouched reserves\n' };
  return { code: 0, stdout: `${text}\n`, stderr: '' };
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
