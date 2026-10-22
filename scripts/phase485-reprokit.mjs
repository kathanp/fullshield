#!/usr/bin/env node
/** Phase 485. Run an allowlisted reproduction block and diff printed numbers. Does not write the file. */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REPROKIT';
const ALLOWED = new Set(['node', 'npm', 'fullshield']);

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function numbersOf(text) {
  return [...text.matchAll(/\d+/g)].map((hit) => hit[0]);
}

export function reproductionBlock(markdown) {
  const match = /```reproduction\r?\n([\s\S]*?)```/.exec(markdown);
  if (match === null) return undefined;
  return (match[1] ?? '').trim();
}

export function holdoutNames(registry) {
  const apps = Array.isArray(registry.apps) ? registry.apps : [];
  return apps.filter((app) => app.status === 'untouched').map((app) => app.name);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const file = arg(argv, '--file');
  const registryPath = arg(argv, '--registry');
  if (file === undefined) return { code: 2, stdout: '', stderr: 'usage: --file <markdown>\n' };
  const before = readFileSync(file);
  const markdown = before.toString('utf8');
  const block = reproductionBlock(markdown);
  if (block === undefined) return { code: 0, stdout: 'no reproduction block\n', stderr: '' };
  const registry = registryPath === undefined ? { apps: [] } : JSON.parse(readFileSync(registryPath, 'utf8'));
  const banned = new Set(holdoutNames(registry));
  const lines = block.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const printed = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    const program = parts[0];
    if (program === 'curl') return { code: 1, stdout: '', stderr: 'refused curl\n' };
    if (program === undefined || !ALLOWED.has(program)) {
      return { code: 1, stdout: '', stderr: `refused program ${String(program)}\n` };
    }
    for (const part of parts.slice(1)) {
      if (banned.has(part) || banned.has(basename(part))) {
        return { code: 1, stdout: '', stderr: `refused untouched holdout ${part}\n` };
      }
    }
    const exe = program === 'node' ? process.execPath : program;
    const child = spawnSync(exe, parts.slice(1), { encoding: 'utf8' });
    if (child.status !== 0) return { code: child.status ?? 1, stdout: child.stdout ?? '', stderr: child.stderr ?? '' };
    printed.push(child.stdout ?? '');
  }
  if (!readFileSync(file).equals(before)) return { code: 1, stdout: '', stderr: 'reproduction file was written\n' };
  const expectedLine = markdown.split(/\r?\n/).find((line) => line.startsWith('numbers:'));
  const expected = numbersOf(expectedLine ?? '');
  const actual = numbersOf(printed.join('\n'));
  if (expected.join(',') !== actual.join(',')) {
    return { code: 1, stdout: '', stderr: `number mismatch expected ${expected.join(',')} printed ${actual.join(',')}\n` };
  }
  return { code: 0, stdout: 'reproduction matches\n', stderr: '' };
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
