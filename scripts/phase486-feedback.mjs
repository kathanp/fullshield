#!/usr/bin/env node
/** Phase 486. Append a local false-positive note. Does not upload. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FEEDBACK';
export const INIT_TEMPLATE = `# fullshield\n.fullshield/feedback.json\n`;
const SECRET = /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 2, stdout: '', stderr: 'FS-E\n' };
  if (argv.includes('--print-template')) return { code: 0, stdout: INIT_TEMPLATE, stderr: '' };
  const fingerprint = arg(argv, '--fingerprint');
  const scanPath = arg(argv, '--scan');
  const note = arg(argv, '--note') ?? '';
  const outDir = arg(argv, '--out');
  if (fingerprint === undefined || scanPath === undefined || outDir === undefined) {
    return { code: 2, stdout: '', stderr: 'FS-E\n' };
  }
  const scan = JSON.parse(readFileSync(scanPath, 'utf8'));
  const findings = Array.isArray(scan.findings) ? scan.findings : [];
  const found = findings.find((row) => row.id === fingerprint);
  const dest = join(outDir, '.fullshield', 'feedback.json');
  if (found === undefined) return { code: 2, stdout: '', stderr: 'FS-E\n' };
  const witness = {
    file: found.file,
    line: found.line,
  };
  const record = { fingerprint, witness, note };
  mkdirSync(dirname(dest), { recursive: true });
  const prior = existsSync(dest) ? JSON.parse(readFileSync(dest, 'utf8')) : [];
  prior.push(record);
  writeFileSync(dest, JSON.stringify(prior, null, 2));
  const warning = SECRET.test(note) ? 'local warning: note matches a secret format; file stays local\n' : '';
  return { code: 0, stdout: `${warning}wrote ${dest}\n`, stderr: '' };
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
