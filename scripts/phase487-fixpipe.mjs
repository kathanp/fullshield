#!/usr/bin/env node
/** Phase 487. Candidate fixture from a local feedback record. Does not network. */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXPIPE';
export const DEFAULT_RUNNER_INCLUDES = ['test/unit/**/*.test.ts', 'test/e2e/**/*.test.ts'];

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function normalize(file) {
  return file.replaceAll('\\', '/');
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  if (argv.includes('--print-includes')) {
    return { code: 0, stdout: `${DEFAULT_RUNNER_INCLUDES.join('\n')}\n`, stderr: '' };
  }
  const feedbackPath = arg(argv, '--feedback');
  const root = arg(argv, '--root');
  if (feedbackPath === undefined || root === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --feedback <file> --root <dir>\n' };
  }
  const doc = JSON.parse(readFileSync(feedbackPath, 'utf8'));
  const rows = Array.isArray(doc) ? doc : [doc];
  const row = rows[0];
  if (row === undefined) return { code: 2, stdout: '', stderr: 'empty feedback\n' };
  const witness = Array.isArray(row.witness) ? row.witness[0] : row.witness;
  const file = normalize(String(witness?.file ?? ''));
  const id = String(row.fingerprint);
  const dest = join(root, 'test', 'fixtures', 'candidates', id);
  mkdirSync(dest, { recursive: true });
  if (file.includes('/bench/') || file.startsWith('bench/')) {
    writeFileSync(join(dest, 'TODO.txt'), 'TODO: rewrite by hand. bench source was not copied.\n');
    return { code: 0, stdout: 'wrote TODO\n', stderr: '' };
  }
  if (!file.includes('test/fixtures/') || file.includes('/candidates/')) {
    return { code: 1, stdout: '', stderr: 'witness is not under test/fixtures\n' };
  }
  const meta = { reviewed: false, fingerprint: id, witness: { file, line: witness?.line } };
  writeFileSync(join(dest, 'meta.json'), JSON.stringify(meta, null, 2));
  return { code: 0, stdout: 'wrote candidate\n', stderr: '' };
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
