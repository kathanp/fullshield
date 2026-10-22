#!/usr/bin/env node
/** Phase 469. Index fixtures by CWE front matter. Does not download a CWE database. */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CWEINDEX';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function frontMatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (match === null) return {};
  const body = match[1] ?? '';
  const out = {};
  for (const line of body.split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return out;
}

export function indexCwe(root) {
  const rulesDir = join(root, 'rules');
  const errors = [];
  const exemptPath = join(root, 'out-of-scope.json');
  const exemptions = new Map();
  if (existsSync(exemptPath)) {
    const doc = JSON.parse(readFileSync(exemptPath, 'utf8'));
    const rows = Array.isArray(doc) ? doc : doc.rows;
    for (const row of rows ?? []) {
      const reason = typeof row.reason === 'string' ? row.reason.trim() : '';
      if (reason.length === 0) errors.push(`exemption without a reason: ${String(row.ruleId)}`);
      exemptions.set(String(row.ruleId), reason);
    }
  }
  if (!existsSync(rulesDir)) return { errors: ['no rules directory'], lines: [] };
  const lines = ['Q10 is still required'];
  for (const name of readdirSync(rulesDir).filter((file) => file.endsWith('.md')).sort()) {
    const ruleId = name.slice(0, -3);
    const matter = frontMatter(readFileSync(join(rulesDir, name), 'utf8'));
    if (matter.cwe === 'none') {
      if ((matter.reason ?? '').length === 0) errors.push(`${ruleId} cwe none needs a reason`);
      lines.push(`${ruleId} exempt cwe-none`);
      continue;
    }
    if (exemptions.has(ruleId)) {
      lines.push(`${ruleId} exempt`);
      continue;
    }
    const positive = join(root, 'fixtures', ruleId, 'positive.js');
    const negative = join(root, 'fixtures', ruleId, 'negative.js');
    if (!existsSync(positive)) errors.push(`${ruleId} missing a positive fixture`);
    if (!existsSync(negative)) errors.push(`${ruleId} missing a negative fixture`);
    lines.push(`${ruleId} cwe=${matter.cwe ?? ''}`);
  }
  return { errors, lines };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const root = arg(argv, '--root');
  if (root === undefined) return { code: 2, stdout: '', stderr: 'usage: --root <dir>\n' };
  const { errors, lines } = indexCwe(root);
  if (errors.length > 0) return { code: 1, stdout: `${lines.join('\n')}\n`, stderr: `${errors.join('\n')}\n` };
  return { code: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
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
