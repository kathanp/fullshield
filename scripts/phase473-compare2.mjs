#!/usr/bin/env node
/** Phase 473. Comparison rows whose reviewed bit a human already set. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_COMPARE2';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function comparisonTable(doc) {
  const rows = Array.isArray(doc.rows) ? doc.rows : [];
  const reviewed = rows.filter((row) => row.reviewed === true);
  if (reviewed.length === 0) return 'no reviewed comparison rows';
  return reviewed
    .map((row) => `${String(row.name)}\t${String(row.count)}`)
    .join('\n');
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const mapPath = arg(argv, '--map');
  if (mapPath === undefined) return { code: 2, stdout: '', stderr: 'usage: --map <file>\n' };
  const doc = JSON.parse(readFileSync(mapPath, 'utf8'));
  return { code: 0, stdout: `${comparisonTable(doc)}\n`, stderr: '' };
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
