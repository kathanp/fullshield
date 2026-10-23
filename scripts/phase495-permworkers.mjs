#!/usr/bin/env node
/** Phase 495. Spawn a scan worker under node --permission. No child-process permission. No fallback row. */
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PERMWORKERS';
export const FALLBACK_ROWS = [];

const WORKER = `const { readFileSync } = require('node:fs');
const target = process.env.FULLSHIELD_WORKER_TARGET;
try {
  readFileSync(target);
  process.stdout.write('read-ok\\n');
} catch (err) {
  process.stdout.write('read-fail\\n');
  process.exitCode = 1;
}
`;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function validateFallback(rows) {
  const errors = [];
  for (const row of rows) {
    if (typeof row.reason !== 'string' || row.reason.trim().length === 0) errors.push('fallback without a reason');
  }
  return errors;
}

export function workerArgv(flagOn, repo, cache) {
  if (!flagOn) return ['-e', WORKER];
  const reads = [repo, cache, realpathSync(repo), realpathSync(cache)];
  const flags = [...new Set(reads)].map((dir) => `--allow-fs-read=${dir}`);
  return ['--permission', ...flags, '-e', WORKER];
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.includes('--check-fallback')) {
    const errors = validateFallback(JSON.parse(arg(argv, '--rows') ?? '[]'));
    if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
    return { code: 0, stdout: 'fallback schema passes\n', stderr: '' };
  }
  const flagOn = env[FLAG] === '1';
  const repo = arg(argv, '--repo');
  const cache = arg(argv, '--cache');
  const target = arg(argv, '--target');
  if (repo === undefined || cache === undefined || target === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --repo <dir> --cache <dir> --target <file>\n' };
  }
  const args = workerArgv(flagOn, repo, cache);
  if (args.includes('--allow-child-process')) {
    return { code: 1, stdout: '', stderr: 'child process permission is not in the default set\n' };
  }
  if (argv.includes('--print-args')) return { code: 0, stdout: `${JSON.stringify(args)}\n`, stderr: '' };
  const child = spawnSync(process.execPath, args, {
    encoding: 'utf8',
    env: { ...env, FULLSHIELD_WORKER_TARGET: target },
  });
  return { code: child.status ?? 1, stdout: child.stdout ?? '', stderr: child.stderr ?? '' };
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
