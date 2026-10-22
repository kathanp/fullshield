#!/usr/bin/env node
/** Phase 488. Fail when a listed false-positive fingerprint reappears without a rule-file note. */
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FPCORPUS';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function checkCorpus(corpusText, findingsText, ruleText) {
  if (corpusText === undefined) return { code: 0, stdout: 'no false-positive corpus\n' };
  const doc = JSON.parse(corpusText);
  const items = Array.isArray(doc.items) ? doc.items : [];
  if (items.length === 0) return { code: 0, stdout: 'no false-positive corpus\n' };
  for (const item of items) {
    if (typeof item.reason !== 'string' || item.reason.trim().length === 0) {
      return { code: 1, stdout: '', stderr: 'empty reason fails the schema\n' };
    }
  }
  const findings = JSON.parse(findingsText);
  const rows = Array.isArray(findings.findings) ? findings.findings : [];
  const emitted = new Set(rows.map((row) => row.id));
  for (const item of items) {
    if (!emitted.has(item.fingerprint)) continue;
    if (!ruleText.includes(item.fingerprint) || !ruleText.includes('why:')) {
      return { code: 1, stdout: '', stderr: `reappearance without a rule-file note: ${item.fingerprint}\n` };
    }
  }
  return { code: 0, stdout: 'false-positive corpus clear\n' };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const corpusPath = arg(argv, '--corpus');
  if (corpusPath === undefined || !existsSync(corpusPath)) {
    return { code: 0, stdout: 'no false-positive corpus\n', stderr: '' };
  }
  const findingsPath = arg(argv, '--findings');
  const rulePath = arg(argv, '--rule');
  const result = checkCorpus(
    readFileSync(corpusPath, 'utf8'),
    findingsPath === undefined ? '{"findings":[]}' : readFileSync(findingsPath, 'utf8'),
    rulePath === undefined ? '' : readFileSync(rulePath, 'utf8'),
  );
  return { code: result.code, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
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
