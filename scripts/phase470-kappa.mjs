#!/usr/bin/env node
/** Phase 470. Cohen's kappa from two human label files. Does not write labels. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_KAPPA';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function fileHash(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function loadLabels(path) {
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  const rows = Array.isArray(doc) ? doc : doc.rows;
  if (!Array.isArray(rows)) throw new Error('label file needs rows');
  return rows.map((row) => ({
    ruleId: String(row.ruleId),
    id: String(row.id),
    label: String(row.label),
  }));
}

/** Cohen's kappa for one paired label list. */
export function cohenKappa(left, right) {
  if (left.length !== right.length) throw new Error('label length mismatch');
  const n = left.length;
  if (n === 0) return { kappa: 1, n: 0 };
  let agree = 0;
  const cats = new Set();
  for (let i = 0; i < n; i += 1) {
    const a = left[i];
    const b = right[i];
    if (a === undefined || b === undefined) throw new Error('missing label');
    cats.add(a);
    cats.add(b);
    if (a === b) agree += 1;
  }
  const po = agree / n;
  let pe = 0;
  for (const cat of cats) {
    const pa = left.filter((value) => value === cat).length / n;
    const pb = right.filter((value) => value === cat).length / n;
    pe += pa * pb;
  }
  const kappa = pe === 1 ? 1 : (po - pe) / (1 - pe);
  return { kappa, n };
}

export function kappaReport(pathA, pathB) {
  const beforeA = fileHash(pathA);
  const beforeB = fileHash(pathB);
  const a = loadLabels(pathA);
  const b = loadLabels(pathB);
  const rules = [...new Set(a.map((row) => row.ruleId))].sort();
  const lines = [];
  for (const ruleId of rules) {
    const left = a.filter((row) => row.ruleId === ruleId);
    const right = b.filter((row) => row.ruleId === ruleId);
    const byId = new Map(right.map((row) => [row.id, row.label]));
    const pairedL = [];
    const pairedR = [];
    for (const row of left) {
      const other = byId.get(row.id);
      if (other === undefined) throw new Error(`missing pair for ${row.id}`);
      pairedL.push(row.label);
      pairedR.push(other);
    }
    const { kappa, n } = cohenKappa(pairedL, pairedR);
    lines.push(`${ruleId} kappa=${kappa.toFixed(2)} n=${n}`);
  }
  if (fileHash(pathA) !== beforeA || fileHash(pathB) !== beforeB) {
    throw new Error('label files changed');
  }
  return lines.join('\n');
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const first = arg(argv, '--a');
  const second = arg(argv, '--b');
  if (first === undefined || second === undefined) {
    return { code: 0, stdout: 'needs second reviewer\n', stderr: '' };
  }
  return { code: 0, stdout: `${kappaReport(first, second)}\n`, stderr: '' };
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
