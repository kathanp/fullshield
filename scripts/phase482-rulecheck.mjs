#!/usr/bin/env node
/** Phase 482. Rule checklist. No numeric score. Older rules do not fail the baseline. */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RULECHECK';
export const REPORT = 'The checklist is not a review.';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function matter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (match === null) return {};
  const out = {};
  for (const line of (match[1] ?? '').split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return out;
}

export function checklist(root, baselineIds) {
  const rulesDir = join(root, 'rules');
  const names = readdirSync(rulesDir).filter((file) => file.endsWith('.md')).sort();
  const rules = [];
  let failNew = false;
  for (const name of names) {
    const ruleId = name.slice(0, -3);
    const text = readFileSync(join(rulesDir, name), 'utf8');
    const meta = matter(text);
    const missing = [];
    if (!existsSync(join(root, 'fixtures', ruleId, 'positive.js'))) missing.push('positive');
    if (!existsSync(join(root, 'fixtures', ruleId, 'negative.js'))) missing.push('negative');
    if (!existsSync(join(root, 'mutants', `${ruleId}.js`))) missing.push('q10');
    const floor = meta.precision ?? '';
    if (floor !== 'ungated' && !/^\d/.test(floor)) missing.push('precision');
    if (!text.includes('FP paragraph:')) missing.push('fp');
    const old = baselineIds.has(ruleId);
    if (!old && missing.length > 0) failNew = true;
    rules.push({ ruleId, old, missing });
  }
  return { report: REPORT, rules, failNew };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const root = arg(argv, '--root');
  const baselinePath = arg(argv, '--baseline');
  if (root === undefined || baselinePath === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --root <dir> --baseline <file>\n' };
  }
  const baselineIds = new Set(
    readFileSync(baselinePath, 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0),
  );
  const result = checklist(root, baselineIds);
  const json = JSON.stringify({ rules: result.rules });
  if (json.includes('"score"')) return { code: 1, stdout: '', stderr: 'score field is banned\n' };
  const stdout = `${result.report}\n${json}\n`;
  return { code: result.failNew ? 1 : 0, stdout, stderr: '' };
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
