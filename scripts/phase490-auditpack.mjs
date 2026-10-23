#!/usr/bin/env node
/** Phase 490. Local evidence folder. Does not upload. Missing SBOM is named, not invented. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_AUDITPACK';
export const FIRST_LINE = 'The contents are locally generated and are not a third-party assessment.';
const SECRET = /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function redact(text) {
  return text.replace(SECRET, (match) => `${match.slice(0, 4)}****`);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 2, stdout: '', stderr: 'FS-E\n' };
  const out = arg(argv, '--out');
  const scanPath = arg(argv, '--scan');
  if (out === undefined || scanPath === undefined || !existsSync(scanPath)) {
    return { code: 2, stdout: '', stderr: 'FS-E scan JSON is required\n' };
  }
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'scan.json'), redact(readFileSync(scanPath, 'utf8')));
  const notes = [];
  const sbom = arg(argv, '--sbom');
  if (sbom !== undefined && existsSync(sbom)) writeFileSync(join(out, 'sbom.json'), readFileSync(sbom, 'utf8'));
  else notes.push('missing SBOM');
  const vex = arg(argv, '--vex');
  if (vex !== undefined && existsSync(vex)) writeFileSync(join(out, 'vex.json'), readFileSync(vex, 'utf8'));
  const unsound = arg(argv, '--unsoundness');
  if (unsound !== undefined && existsSync(unsound)) {
    writeFileSync(join(out, 'unsoundness.md'), readFileSync(unsound, 'utf8'));
  }
  const threat = arg(argv, '--threat');
  if (threat !== undefined && existsSync(threat)) {
    const text = readFileSync(threat, 'utf8');
    const heads = [...text.matchAll(/^#+\s+.+$/gm)].map((hit) => hit[0]);
    writeFileSync(join(out, 'threat-headings.md'), heads.join('\n') + '\n');
  }
  const readme = [FIRST_LINE, ...notes.map((note) => note)].join('\n') + '\n';
  writeFileSync(join(out, 'README.md'), readme);
  return { code: 0, stdout: 'evidence pack written\n', stderr: '' };
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
