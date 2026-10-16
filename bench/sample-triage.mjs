#!/usr/bin/env node
/**
 * Pick unmatched findings for a human to label.
 * Refuses untouched apps. Does not scan.
 *
 *   node bench/sample-triage.mjs --app nodegoat --n 20
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)));

function arg(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return fallback;
  return process.argv[idx + 1] ?? fallback;
}

const app = arg('--app', '');
const n = Number(arg('--n', '20'));
if (app === '') {
  console.error('pass --app');
  process.exit(2);
}
const holdouts = JSON.parse(readFileSync(join(root, 'holdouts.json'), 'utf8'));
const meta = holdouts.apps.find((item) => item.name === app);
if (meta === undefined) {
  console.error(`unknown app ${app}`);
  process.exit(2);
}
if (meta.status === 'untouched') {
  console.error(`${app} is untouched. Phase 37 does not scan it and does not sample findings.`);
  process.exit(1);
}
const findingsFile = join(root, app, 'scan.json');
if (!existsSync(findingsFile)) {
  console.error(`no ${app}/scan.json. This script does not run a scan.`);
  process.exit(1);
}
const report = JSON.parse(readFileSync(findingsFile, 'utf8'));
const findings = Array.isArray(report.findings) ? report.findings : [];
const sample = findings.slice(0, n).map((finding) => ({
  ruleId: finding.ruleId,
  file: finding.file,
  line: finding.line,
  severity: finding.severity,
  label: null,
  reason: '',
}));
const out = join(root, app, 'human-triage.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify({ app, sampled: sample.length, findings: sample }, null, 2)}\n`);
console.log(`wrote ${out} (${sample.length} unlabeled)`);
