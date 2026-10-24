#!/usr/bin/env node
/**
 * Phase 36. After a publish (including a staged one that just became public),
 * poll `npm view fullshield@<version> dist.attestations` for up to 3 hours.
 * Exit 1 if the field stays empty. 0.1.3 shipped this way and must not repeat.
 * The field stays empty until a person approves the staged publish on npmjs.com.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { attestationsPresent } from './release-checks.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';
const WAIT_MS = 3 * 60 * 60 * 1000;
const INTERVAL_MS = 30 * 1000;

function waitLabel(ms) {
  const hours = ms / (60 * 60 * 1000);
  return Number.isInteger(hours) ? `${hours} hours` : `${Math.round(ms / 60000)} minutes`;
}

function versionFromArg() {
  const idx = process.argv.indexOf('--version');
  if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  return pkg.version;
}

function view(version) {
  const result = spawnSync(
    isWindows ? 'npm.cmd' : 'npm',
    ['view', `fullshield@${version}`, 'dist.attestations', '--json'],
    { cwd: root, encoding: 'utf8', shell: isWindows },
  );
  if (result.status !== 0) return null;
  const text = result.stdout.trim();
  if (text === '' || text === 'null') return { dist: {} };
  try {
    const parsed = JSON.parse(text);
    return { dist: { attestations: parsed } };
  } catch {
    return null;
  }
}

function sleep(ms) {
  spawnSync(process.execPath, ['-e', `setTimeout(() => {}, ${ms})`], { stdio: 'ignore' });
}

function main() {
  const version = versionFromArg();
  const deadline = Date.now() + WAIT_MS;
  const label = waitLabel(WAIT_MS);
  console.log(
    `provenance-gate waiting up to ${label} for fullshield@${version} dist.attestations. Approve the staged version on npmjs.com with 2FA.`,
  );
  let last = null;
  do {
    last = view(version);
    if (attestationsPresent(last)) {
      console.log(`provenance-gate fullshield@${version} has dist.attestations`);
      return;
    }
    console.log(`provenance-gate waiting for fullshield@${version} dist.attestations`);
    if (Date.now() + INTERVAL_MS > deadline) break;
    sleep(INTERVAL_MS);
  } while (Date.now() < deadline);
  console.error(
    `provenance-gate FAILED: fullshield@${version} has no dist.attestations after ${label}. Do not treat this publish as done. 0.1.3 was published without provenance because the stage retried after a sigstore 409.`,
  );
  process.exit(1);
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
}
