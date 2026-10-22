/**
 * Phase 263. Deterministic disagreement export. Labels stay null.
 * This file makes no accuracy claim about either tool.
 */
import { readFileSync, writeFileSync } from 'node:fs';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const fullshieldPath = process.argv[2];
const semgrepPath = process.argv[3];
const outPath = process.argv[4];
if (fullshieldPath === undefined || semgrepPath === undefined || outPath === undefined) {
  fail('usage: semgrep-diff.mjs <fullshield.json> <semgrep.json> <out.json>');
}

function keys(file) {
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const rows = Array.isArray(raw.findings) ? raw.findings : [];
  return rows
    .map((row) => `${row.class ?? ''}|${row.file ?? ''}|${row.line ?? ''}`)
    .sort();
}

const left = keys(fullshieldPath);
const right = keys(semgrepPath);
const rightSet = new Set(right);
const leftSet = new Set(left);
const both = left.filter((key) => rightSet.has(key));
const onlyFullshield = left.filter((key) => !rightSet.has(key));
const onlySemgrep = right.filter((key) => !leftSet.has(key));
const disagreements = [...onlyFullshield, ...onlySemgrep].map((key) => ({ key, label: null }));

writeFileSync(outPath, `${JSON.stringify({ both, onlyFullshield, onlySemgrep, disagreements }, null, 2)}\n`);
console.log(`both ${both.length} only-fullshield ${onlyFullshield.length} only-semgrep ${onlySemgrep.length}`);
