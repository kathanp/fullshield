#!/usr/bin/env node
/** Phase 484. Commit-shape check against tuning apps, untouched results, and copied fixtures. */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ANTIOVERFIT';
const FIXTURE_REQUIRED = 'a handwritten fixture under test/fixtures/ is required';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stat = statSync(path);
    if (stat.isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

export function parseManifest(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^([AMD])\s+(\S+)/.exec(line.trim());
    if (match === null) continue;
    rows.push({ status: match[1], path: match[2] });
  }
  return rows;
}

export function checkDiff(manifest, registry, root) {
  const errors = [];
  const apps = Array.isArray(registry.apps) ? registry.apps : [];
  const tuning = new Set(apps.filter((app) => app.status === 'tuning').map((app) => app.name));
  const untouched = new Set(apps.filter((app) => app.status === 'untouched').map((app) => app.name));
  const rule = manifest.some((row) => row.path.includes('/sast/') || row.path.startsWith('rules/') || row.path.includes('/rules/'));
  const tuningEdit = manifest.some((row) => {
    const parts = row.path.split('/');
    const bench = parts.indexOf('bench');
    return bench !== -1 && tuning.has(parts[bench + 1] ?? '');
  });
  const fixture = manifest.some((row) => row.path.includes('test/fixtures/'));
  if (rule && tuningEdit && !fixture) errors.push(FIXTURE_REQUIRED);
  for (const row of manifest) {
    if (row.status !== 'A') continue;
    const parts = row.path.split('/');
    const bench = parts.indexOf('bench');
    const name = bench === -1 ? undefined : parts[bench + 1];
    if (name !== undefined && untouched.has(name) && row.path.endsWith('.json')) {
      errors.push(`untouched results file fails: ${row.path}`);
    }
  }
  for (const row of manifest) {
    if (!row.path.includes('test/fixtures/') || row.status !== 'A') continue;
    const added = join(root, row.path);
    let bytes;
    try {
      bytes = readFileSync(added);
    } catch {
      continue;
    }
    for (const name of tuning) {
      const dir = join(root, 'bench', name);
      let files = [];
      try {
        files = walk(dir);
      } catch {
        continue;
      }
      for (const file of files) {
        if (readFileSync(file).equals(bytes)) {
          errors.push(`fixture copies tuning-app bytes (${relative(root, file)})`);
        }
      }
    }
  }
  return errors;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const diffPath = arg(argv, '--diff');
  const registryPath = arg(argv, '--registry');
  const root = arg(argv, '--root');
  if (diffPath === undefined || registryPath === undefined || root === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --diff <file> --registry <file> --root <dir>\n' };
  }
  const errors = checkDiff(
    parseManifest(readFileSync(diffPath, 'utf8')),
    JSON.parse(readFileSync(registryPath, 'utf8')),
    root,
  );
  if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  return { code: 0, stdout: 'commit shape passes\n', stderr: '' };
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
