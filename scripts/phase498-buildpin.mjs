#!/usr/bin/env node
/** Phase 498. Lint workflow pins and the install command. Does not rewrite workflows. */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BUILDPIN';
const SHA = /@[0-9a-f]{40}\b/;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function lintWorkflow(text, name) {
  const errors = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const uses = /^\s*-?\s*uses:\s*(\S+)/.exec(line);
    if (uses !== null) {
      const action = uses[1] ?? '';
      if (!SHA.test(action)) {
        errors.push(`${name}: ${action} has no SHA`);
        if (/@v\d+\b/.test(action)) errors.push(`sub-point: floating action tag ${action}`);
      }
    }
    if (/^\s*(-\s*)?run:\s*npm install\b/.test(line) || /\bnpm install\b/.test(line)) {
      errors.push(`${name}: npm install fails the lint`);
      errors.push('sub-point: npm install is not npm ci --ignore-scripts');
    }
    if (/\bnpm ci\b/.test(line) && !line.includes('npm ci --ignore-scripts')) {
      errors.push(`${name}: install step must be npm ci --ignore-scripts`);
      errors.push('sub-point: npm ci is missing --ignore-scripts');
    }
    const node = /node-version:\s*(\S+)/.exec(line);
    if (node !== null) {
      const version = (node[1] ?? '').replace(/['"]/g, '');
      if (!/^\d+\.\d+\.\d+$/.test(version)) {
        errors.push(`${name}: node is not pinned (${version})`);
        errors.push(`sub-point: node pin must be x.y.z (${version})`);
      }
    }
  }
  const npmPinned = /npm@[0-9]+\.[0-9]+\.[0-9]+/.test(text) || /npm-version:\s*['"]?\d+\.\d+\.\d+/.test(text);
  if (!npmPinned && /setup-node/.test(text)) {
    errors.push(`${name}: npm is not pinned`);
    errors.push('sub-point: npm pin is missing beside setup-node');
  }
  return errors;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const file = arg(argv, '--workflow');
  const dir = arg(argv, '--workflows');
  const paths = [];
  if (file !== undefined) paths.push(file);
  if (dir !== undefined) {
    for (const name of readdirSync(dir)) {
      if (name.endsWith('.yml') || name.endsWith('.yaml')) paths.push(join(dir, name));
    }
  }
  if (paths.length === 0) return { code: 2, stdout: '', stderr: 'usage: --workflow <file>\n' };
  const before = paths.map((path) => createHash('sha256').update(readFileSync(path)).digest('hex'));
  const errors = [];
  for (const path of paths) errors.push(...lintWorkflow(readFileSync(path, 'utf8'), path));
  const after = paths.map((path) => createHash('sha256').update(readFileSync(path)).digest('hex'));
  if (before.join() !== after.join()) return { code: 1, stdout: '', stderr: 'lint rewrote a workflow\n' };
  if (errors.length > 0) {
    const park = argv.includes('--repo') ? 'parked (S3): workflow lint failed and this phase does not rewrite workflows\n' : '';
    return { code: 1, stdout: '', stderr: `${park}${errors.join('\n')}\n` };
  }
  return { code: 0, stdout: 'workflow pins pass\n', stderr: '' };
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
