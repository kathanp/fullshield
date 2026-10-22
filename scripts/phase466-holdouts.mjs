#!/usr/bin/env node
/**
 * Phase 466. Schema-check untouched holdout rows. Does not write bench/holdouts.json.
 * Parks when the human has not named ten repos.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOLDOUTS';
const SHA = /^[0-9a-f]{40}$/;
const PLACEHOLDER_NAMES = new Set(['placeholder', 'todo', 'tbd', 'changeme', 'unnamed', 'fixme', 'repo', 'holdout']);

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function validateUntouchedRows(rows, resultsDir) {
  const errors = [];
  if (!Array.isArray(rows) || rows.length !== 10) {
    errors.push('ten untouched rows are required');
  }
  const list = Array.isArray(rows) ? rows : [];
  const seenNames = new Set();
  for (const row of list) {
    if (row === null || typeof row !== 'object') {
      errors.push('row must be an object');
      continue;
    }
    if (row.status !== 'untouched') errors.push(`status must be untouched (${String(row.status)})`);
    if (row.status === 'seen') errors.push('status seen fails');
    if (row.status === 'tuning') errors.push('status tuning fails');
    if (row.reviewed !== false) errors.push('reviewed: true row fails');
    if (row.firstRunDate !== '' && row.firstRunDate !== null) errors.push('firstRunDate must be empty');
    if (typeof row.name !== 'string' || row.name.length === 0) errors.push('name is required');
    if (typeof row.name === 'string' && PLACEHOLDER_NAMES.has(row.name.toLowerCase())) {
      errors.push(`placeholder name fails (${row.name})`);
    }
    if (typeof row.name === 'string' && seenNames.has(row.name)) errors.push(`duplicate name fails (${row.name})`);
    if (typeof row.name === 'string') seenNames.add(row.name);
    if (typeof row.repo !== 'string' || !row.repo.startsWith('https://')) errors.push('repo must be an https URL');
    if (typeof row.sha !== 'string' || !SHA.test(row.sha)) errors.push('sha must be a pinned commit');
    if (typeof row.name === 'string' && resultsDir !== undefined) {
      const hits = [
        join(resultsDir, `${row.name}.json`),
        join(resultsDir, row.name, 'scan.json'),
        join(resultsDir, row.name, 'findings.json'),
      ];
      if (hits.some((path) => existsSync(path))) errors.push(`results file for ${row.name} fails the commit check`);
    }
  }
  return errors;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const namesPath = arg(argv, '--names');
  if (namesPath === undefined) {
    return {
      code: 3,
      stdout: '',
      stderr: 'parked (S3): human has not named ten holdout repos\n',
    };
  }
  const rows = JSON.parse(readFileSync(namesPath, 'utf8'));
  const errors = validateUntouchedRows(rows, arg(argv, '--results'));
  if (errors.length > 0) {
    return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  }
  return { code: 0, stdout: 'schema passes\n', stderr: '' };
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
