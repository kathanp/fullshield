#!/usr/bin/env node
/**
 * Phase 76. Writes unlabeled precision rows. Never fills label, reviewer, or note.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] ?? fallback;
}

export function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

export function sampleFindings(findings, perRule, seed) {
  const rand = mulberry32(seed);
  const byRule = new Map();
  for (const finding of findings) {
    const list = byRule.get(finding.ruleId) ?? [];
    list.push(finding);
    byRule.set(finding.ruleId, list);
  }
  const rows = [];
  for (const ruleId of [...byRule.keys()].sort()) {
    const list = [...(byRule.get(ruleId) ?? [])].sort((a, b) =>
      `${a.file ?? ''}:${a.line ?? 0}`.localeCompare(`${b.file ?? ''}:${b.line ?? 0}`),
    );
    const copy = [...list];
    const picked = [];
    while (picked.length < perRule && copy.length > 0) {
      const index = Math.floor(rand() * copy.length);
      picked.push(copy.splice(index, 1)[0]);
    }
    for (const finding of picked) {
      rows.push({
        ruleId: finding.ruleId,
        file: finding.file ?? '',
        line: finding.line ?? 0,
        severity: finding.severity,
        id: finding.id,
        label: null,
        reviewer: null,
        note: null,
      });
    }
  }
  return rows;
}

function main() {
  const app = arg('--app');
  if (app === undefined) {
    console.error('precision-sample: --app is required');
    process.exit(2);
  }
  const perRule = Number(arg('--per-rule', '10'));
  const seed = Number(arg('--seed', '1'));
  const from = arg('--from', join(root, 'bench', app, 'scan.json'));
  const out = arg('--out', join(root, 'bench', 'precision', `${app}.todo.json`));
  const doc = JSON.parse(readFileSync(from, 'utf8'));
  const findings = Array.isArray(doc) ? doc : doc.findings;
  if (!Array.isArray(findings)) {
    console.error('precision-sample: scan JSON has no findings array');
    process.exit(2);
  }
  const rows = sampleFindings(findings, perRule, seed);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(rows, null, 2)}\n`);
  console.log(`precision-sample: wrote ${rows.length} unlabeled rows to ${out}`);
}

const invoked = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) main();
