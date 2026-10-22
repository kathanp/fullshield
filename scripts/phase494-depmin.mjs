#!/usr/bin/env node
/** Phase 494. Hard-dependency allow list is empty. Does not delete existing dependencies. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEPMIN';
export const ALLOW = [];

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function checkPackage(pkg, allow) {
  const errors = [];
  const deps = pkg.dependencies ?? {};
  const names = Object.keys(deps);
  for (const name of names) {
    if (!allow.includes(name)) errors.push(`dependency is not on the allow list: ${name}`);
  }
  for (const name of allow) {
    if (!Object.hasOwn(deps, name)) errors.push(`allow list name missing from dependencies: ${name}`);
  }
  const peers = pkg.peerDependencies ?? {};
  const meta = pkg.peerDependenciesMeta ?? {};
  for (const name of Object.keys(peers)) {
    if (meta[name]?.optional !== true) errors.push(`peer without optional: true: ${name}`);
  }
  return errors;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const packagePath = arg(argv, '--package');
  if (packagePath === undefined) return { code: 2, stdout: '', stderr: 'usage: --package <file>\n' };
  const before = createHash('sha256').update(readFileSync(packagePath)).digest('hex');
  const pkg = JSON.parse(readFileSync(packagePath, 'utf8'));
  const names = Object.keys(pkg.dependencies ?? {});
  if (!argv.includes('--check') && names.length > 0 && ALLOW.length === 0) {
    const peers = pkg.peerDependencies ?? {};
    const meta = pkg.peerDependenciesMeta ?? {};
    const peerLines = Object.keys(peers).map((name) => {
      const optional = meta[name]?.optional === true ? 'optional' : 'not optional';
      return `sub-point: peer ${name} is ${optional}`;
    });
    const lines = [
      `parked (S3): hard dependencies already exist (${names.join(', ')})`,
      'sub-point: allow list stays empty',
      'sub-point: this phase does not delete dependencies',
      'sub-point: later edits are R1',
      ...peerLines,
    ];
    return { code: 3, stdout: '', stderr: `${lines.join('\n')}\n` };
  }
  const errors = checkPackage(pkg, ALLOW);
  if (createHash('sha256').update(readFileSync(packagePath)).digest('hex') !== before) {
    return { code: 1, stdout: '', stderr: 'dependencies were modified\n' };
  }
  if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  return { code: 0, stdout: 'allow list matches\n', stderr: '' };
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
