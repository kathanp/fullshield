#!/usr/bin/env node
/**
 * Diff a fresh default scan of each pinned repo against bench/snapshots/realworld.json.
 * Prints added and removed keys per repo. Exits 1 when any added key is not listed in
 * bench/snapshots/realworld-approved.txt. That file is human-edited (R1). This script
 * only reads it.
 *
 *   node scripts/realworld-diff.mjs
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  argValue,
  diffKeys,
  findingKey,
  formatRepoDiff,
  gateExitCode,
  loadRegistry,
  materializeRepo,
  readApprovedKeys,
  scanWithCli,
} from './realworld-lib.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export async function runDiff(argv, deps = {}) {
  const registryPath = resolve(argValue(argv, '--registry', join(root, 'bench/realworld.json')));
  const snapshotPath = resolve(argValue(argv, '--snapshot', join(root, 'bench/snapshots/realworld.json')));
  const approvedPath = resolve(
    argValue(argv, '--approved', join(root, 'bench/snapshots/realworld-approved.txt')),
  );
  const cacheDir = resolve(argValue(argv, '--cache', join(root, 'bench/.cache/realworld')));
  const cli = resolve(argValue(argv, '--cli', join(root, 'dist/cli/index.js')));
  const stdout = deps.stdout ?? ((text) => process.stdout.write(text));
  const stderr = deps.stderr ?? ((text) => process.stderr.write(text));
  const spawn = deps.spawn ?? spawnSync;

  if (!existsSync(snapshotPath)) {
    stderr(`realworld-diff: missing snapshot ${snapshotPath}\nRun node scripts/realworld-snapshot.mjs and commit the result.\n`);
    return 2;
  }

  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8'));
  const repos = loadRegistry(registryPath);
  const approved = readApprovedKeys(approvedPath);
  const blocks = [];
  const addedAll = [];
  for (const entry of repos) {
    const dir = await materializeRepo(entry, cacheDir, { spawn: deps.spawn });
    const findings = deps.scanFindings
      ? await deps.scanFindings(dir)
      : scanWithCli(dir, cli, spawn, root);
    const keys = findings.map((finding) => findingKey(finding));
    const prior = snapshot.repos?.[entry.name]?.keys ?? [];
    const diff = diffKeys(prior, keys);
    addedAll.push(...diff.added);
    blocks.push(formatRepoDiff(entry.name, diff));
  }
  stdout(`${blocks.join('\n')}\n`);
  return gateExitCode(addedAll, approved);
}

function isDirectRun() {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  return import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  runDiff(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    });
}
