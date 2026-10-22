#!/usr/bin/env node
/** Phase 472. Compare a toolchain pin before a differential command. Does not install. */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TOOLCHAINPIN';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function comparePin(pin, local) {
  const fields = ['node', 'npm', 'semgrep'];
  const mismatches = [];
  for (const field of fields) {
    if (pin[field] !== local[field]) mismatches.push({ field, pinned: pin[field], local: local[field] });
  }
  return mismatches;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const pinPath = arg(argv, '--pin');
  if (pinPath === undefined) return { code: 2, stdout: '', stderr: 'usage: --pin <file>\n' };
  const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
  const local = {
    node: arg(argv, '--node'),
    npm: arg(argv, '--npm'),
    semgrep: arg(argv, '--semgrep'),
  };
  const mismatches = comparePin(pin, local);
  if (mismatches.length > 0) {
    const lines = mismatches.map(
      (row) => `${row.field} pinned ${String(row.pinned)} local ${String(row.local)}`,
    );
    return { code: 1, stdout: '', stderr: `${lines.join('\n')}\n` };
  }
  const marker = arg(argv, '--continue-marker');
  if (marker !== undefined) {
    const child = spawnSync(process.execPath, ['-e', `require('node:fs').writeFileSync(process.argv[1], 'ran')`, marker], {
      encoding: 'utf8',
    });
    if (child.status !== 0) return { code: child.status ?? 1, stdout: child.stdout ?? '', stderr: child.stderr ?? '' };
  }
  return { code: 0, stdout: 'toolchain match\n', stderr: '' };
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
