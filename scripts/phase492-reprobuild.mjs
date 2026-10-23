#!/usr/bin/env node
/** Phase 492. Diff two build trees. Allow-listed files need a reason. Does not rewrite bytes. */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REPROBUILD';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

function hashFile(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function diffTrees(leftDir, rightDir, allow) {
  const errors = [];
  for (const row of allow) {
    if (typeof row.reason !== 'string' || row.reason.trim().length === 0) {
      errors.push(`allow row with an empty reason: ${String(row.path)}`);
    }
  }
  if (errors.length > 0) return errors;
  const allowed = new Map(allow.map((row) => [row.path, row.reason]));
  const leftFiles = new Map(walk(leftDir).map((path) => [relative(leftDir, path).replaceAll('\\', '/'), hashFile(path)]));
  const rightFiles = new Map(walk(rightDir).map((path) => [relative(rightDir, path).replaceAll('\\', '/'), hashFile(path)]));
  const names = new Set([...leftFiles.keys(), ...rightFiles.keys()]);
  for (const name of [...names].sort()) {
    if (leftFiles.get(name) === rightFiles.get(name)) continue;
    if (!allowed.has(name)) errors.push(`byte difference is not allowed: ${name}`);
  }
  return errors;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const left = arg(argv, '--left');
  const right = arg(argv, '--right');
  const allowPath = arg(argv, '--allow');
  if (left === undefined || right === undefined || allowPath === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --left <dir> --right <dir> --allow <file>\n' };
  }
  const watch = arg(argv, '--watch');
  const beforeWatch = watch === undefined ? undefined : hashFile(join(left, watch));
  const allow = JSON.parse(readFileSync(allowPath, 'utf8'));
  const rows = Array.isArray(allow) ? allow : allow.files;
  const errors = diffTrees(left, right, rows ?? []);
  if (watch !== undefined && beforeWatch !== undefined && hashFile(join(left, watch)) !== beforeWatch) {
    return { code: 1, stdout: '', stderr: 'checker rewrote the tarball\n' };
  }
  if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  return { code: 0, stdout: 'rebuild bytes match\n', stderr: '' };
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
