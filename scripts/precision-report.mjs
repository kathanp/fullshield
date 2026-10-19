#!/usr/bin/env node
/**
 * Phase 76. Precision only from rows a human labeled. Unlabeled files are refused.
 */
import { readFileSync, writeFileSync } from 'node:fs';

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] ?? fallback;
}

export function wilsonInterval(successes, total, z = 1.96) {
  if (total === 0) return { low: 0, high: 0 };
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total)) / denom;
  return { low: Math.max(0, center - margin), high: Math.min(1, center + margin) };
}

export function precisionReport(rows) {
  const labeled = rows.filter((row) => row.label === 'tp' || row.label === 'fp' || row.label === 'unsure');
  if (labeled.length === 0) {
    throw new Error('precision-report: no labeled rows');
  }
  const byRule = new Map();
  for (const row of labeled) {
    const bucket = byRule.get(row.ruleId) ?? { tp: 0, fp: 0, unsure: 0 };
    if (row.label === 'tp') bucket.tp += 1;
    else if (row.label === 'fp') bucket.fp += 1;
    else bucket.unsure += 1;
    byRule.set(row.ruleId, bucket);
  }
  const lines = ['# Precision', '', 'Computed only from human labels. Unreviewed until those labels exist.', ''];
  lines.push('| rule | n | precision | Wilson 95% |');
  lines.push('|---|---|---|---|');
  for (const ruleId of [...byRule.keys()].sort()) {
    const bucket = byRule.get(ruleId);
    const n = bucket.tp + bucket.fp;
    if (n < 10) {
      lines.push(`| ${ruleId} | ${n} | insufficient sample | — |`);
      continue;
    }
    const precision = bucket.tp / n;
    const interval = wilsonInterval(bucket.tp, n);
    lines.push(
      `| ${ruleId} | ${n} | ${precision.toFixed(3)} | ${interval.low.toFixed(3)}–${interval.high.toFixed(3)} |`,
    );
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const input = arg('--from');
  if (input === undefined) {
    console.error('precision-report: --from is required');
    process.exit(2);
  }
  const rows = JSON.parse(readFileSync(input, 'utf8'));
  const markdown = precisionReport(rows);
  const out = arg('--out');
  if (out !== undefined) writeFileSync(out, markdown);
  else process.stdout.write(markdown);
}

if (process.argv[1] !== undefined && process.argv[1].endsWith('precision-report.mjs')) main();
