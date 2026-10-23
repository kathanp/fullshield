#!/usr/bin/env node
/** Phase 475. Wilson lower bound split by framework. Does not write the floor file. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRECFW';
const Z = 1.96;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function fileHash(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Wilson 95% lower bound for tp successes out of n decided labels. */
export function wilsonLower(tp, n) {
  if (n === 0) return 0;
  const p = tp / n;
  const z2 = Z * Z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const margin = (Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return center - margin;
}

export function precisionByFramework(labels, floors) {
  const groups = new Map();
  for (const row of labels) {
    const framework = typeof row.framework === 'string' && row.framework.length > 0 ? row.framework : 'unknown';
    const slot = groups.get(framework) ?? { tp: 0, fp: 0 };
    if (row.label === 'TP') slot.tp += 1;
    else if (row.label === 'FP') slot.fp += 1;
    groups.set(framework, slot);
  }
  if (!groups.has('unknown')) groups.set('unknown', { tp: 0, fp: 0 });
  const cells = [];
  let failed = false;
  for (const framework of [...groups.keys()].sort()) {
    const slot = groups.get(framework);
    if (slot === undefined) continue;
    const n = slot.tp + slot.fp;
    if (n < 20) {
      cells.push({ framework, status: 'ungated', n });
      continue;
    }
    const lower = wilsonLower(slot.tp, n);
    const floor = floors[framework];
    const status = typeof floor === 'number' && lower < floor ? 'fail' : 'pass';
    if (status === 'fail') failed = true;
    cells.push({ framework, status, n, lower });
  }
  return { cells, failed };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const labelsPath = arg(argv, '--labels');
  const floorsPath = arg(argv, '--floors');
  if (labelsPath === undefined || floorsPath === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --labels <file> --floors <file>\n' };
  }
  const before = fileHash(floorsPath);
  const labelsDoc = JSON.parse(readFileSync(labelsPath, 'utf8'));
  const floors = JSON.parse(readFileSync(floorsPath, 'utf8'));
  const labels = Array.isArray(labelsDoc) ? labelsDoc : labelsDoc.rows;
  const { cells, failed } = precisionByFramework(labels ?? [], floors);
  if (fileHash(floorsPath) !== before) {
    return { code: 1, stdout: '', stderr: 'floor file changed\n' };
  }
  const text = `${JSON.stringify({ cells })}\n`;
  return { code: failed ? 1 : 0, stdout: text, stderr: '' };
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
