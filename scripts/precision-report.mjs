#!/usr/bin/env node
/**
 * Per-rule precision from human-labeled precision todo files.
 * Rows with label null are ignored. n = tp + fp. unsure is not in n.
 * Wilson 95% interval. n < 10 prints "insufficient sample".
 * Zero human labels: refuse.
 *
 *   node scripts/precision-report.mjs [file-or-dir] --out bench/precision/REPORT.md
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const HUMAN = new Set(['tp', 'fp', 'unsure']);
const Z = 1.959963984540054;

function wilson95(tp, n) {
  const p = tp / n;
  const z2 = Z * Z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const margin = (Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { low: center - margin, high: center + margin };
}

function asRows(input) {
  if (Array.isArray(input)) return input;
  if (input !== null && typeof input === 'object' && Array.isArray(input.rows)) return input.rows;
  return [];
}

/** Markdown report. Throws when no row has a human label. */
export function renderPrecisionReport(input) {
  const buckets = new Map();
  let human = 0;
  for (const row of asRows(input)) {
    const label = row?.label;
    if (label === null || label === undefined || label === '') continue;
    if (!HUMAN.has(label)) {
      throw new Error(`label must be tp, fp, unsure, or null (got ${JSON.stringify(label)})`);
    }
    human += 1;
    const ruleId = String(row.ruleId ?? '');
    const slot = buckets.get(ruleId) ?? { tp: 0, fp: 0, unsure: 0 };
    slot[label] += 1;
    buckets.set(ruleId, slot);
  }
  if (human === 0) throw new Error('zero labels');
  const lines = [
    '# Precision report',
    '',
    'Only rows a human labeled (`tp`, `fp`, or `unsure`) are counted. `label: null` is ignored. Precision is tp / (tp + fp). `unsure` is not in n. The interval is the Wilson score at 95%. A rule with n below 10 is an insufficient sample.',
    '',
    '| rule | tp | fp | unsure | n | precision | wilson 95% | note |',
    '|---|---:|---:|---:|---:|---:|---|---|',
  ];
  for (const ruleId of [...buckets.keys()].sort()) {
    const slot = buckets.get(ruleId) ?? { tp: 0, fp: 0, unsure: 0 };
    const n = slot.tp + slot.fp;
    if (n === 0) {
      lines.push(`| ${ruleId} | ${slot.tp} | ${slot.fp} | ${slot.unsure} | 0 | n/a | n/a | insufficient sample |`);
      continue;
    }
    const precision = (slot.tp / n).toFixed(3);
    const interval = wilson95(slot.tp, n);
    const span = `[${interval.low.toFixed(3)}, ${interval.high.toFixed(3)}]`;
    const note = n < 10 ? 'insufficient sample' : '';
    lines.push(`| ${ruleId} | ${slot.tp} | ${slot.fp} | ${slot.unsure} | ${n} | ${precision} | ${span} | ${note} |`);
  }
  lines.push('');
  return lines.join('\n');
}

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return undefined;
  const value = process.argv[idx + 1];
  if (value === undefined || value.startsWith('--')) return undefined;
  return value;
}

function jsonFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => join(dir, entry.name))
    .sort();
}

function isDirectory(target) {
  try {
    readdirSync(target);
    return !target.endsWith('.json');
  } catch {
    return false;
  }
}

function collect(target) {
  if (!existsSync(target)) throw new Error(`missing ${target}`);
  const paths = isDirectory(target) ? jsonFiles(target) : [target];
  const rows = [];
  for (const path of paths) {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    rows.push(...asRows(parsed));
  }
  return rows;
}

function main() {
  const positional = process.argv.slice(2).filter((token, index, all) => {
    if (token === '--out') return false;
    if (index > 0 && all[index - 1] === '--out') return false;
    return !token.startsWith('--');
  });
  const target = positional[0] ?? join(root, 'bench', 'precision');
  const out = arg('--out') ?? join(root, 'bench', 'precision', 'REPORT.md');
  let text = '';
  try {
    text = renderPrecisionReport(collect(target));
  } catch (error) {
    console.error(`precision-report: ${error instanceof Error ? error.message : error}`);
    process.exit(1);
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
