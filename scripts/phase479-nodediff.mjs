#!/usr/bin/env node
/** Phase 479. Byte-diff finding JSON. Differences are not exempted. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NODEDIFF';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function canonicalFindings(doc) {
  const rows = Array.isArray(doc) ? doc : doc.findings;
  const keys = (rows ?? []).map((row) =>
    JSON.stringify({
      ruleId: row.ruleId,
      file: row.file,
      line: row.line,
      severity: row.severity,
      extra: row,
    }),
  );
  keys.sort();
  return keys.join('\n');
}

export function diffFindings(leftText, rightText) {
  const left = canonicalFindings(JSON.parse(leftText));
  const right = canonicalFindings(JSON.parse(rightText));
  if (left === right) return { ok: true, text: 'findings match\n' };
  return { ok: false, text: 'finding bytes differ\n' };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const left = arg(argv, '--left');
  const right = arg(argv, '--right');
  if (left === undefined || right === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --left <json> --right <json>\n' };
  }
  const result = diffFindings(readFileSync(left, 'utf8'), readFileSync(right, 'utf8'));
  if (!result.ok) return { code: 1, stdout: '', stderr: result.text };
  return { code: 0, stdout: result.text, stderr: '' };
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
