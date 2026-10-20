#!/usr/bin/env node
/**
 * Write bench/snapshots/realworld.json: default-scan keys
 * (ruleId, file, line, severity) for every pin in bench/realworld.json.
 *
 *   node scripts/realworld-snapshot.mjs
 *   node scripts/realworld-snapshot.mjs --registry bench/realworld.json --out bench/snapshots/realworld.json
 *
 * Checkouts go to bench/.cache/realworld. They are not installed and not executed.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  argValue,
  buildSnapshot,
  findingKey,
  loadRegistry,
  materializeRepo,
  scanWithCli,
} from './realworld-lib.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export async function runSnapshot(argv, deps = {}) {
  const registryPath = resolve(argValue(argv, '--registry', join(root, 'bench/realworld.json')));
  const outPath = resolve(argValue(argv, '--out', join(root, 'bench/snapshots/realworld.json')));
  const cacheDir = resolve(argValue(argv, '--cache', join(root, 'bench/.cache/realworld')));
  const cli = resolve(argValue(argv, '--cli', join(root, 'dist/cli/index.js')));
  const spawn = deps.spawn ?? spawnSync;
  const repos = loadRegistry(registryPath);
  const built = {};
  for (const entry of repos) {
    const dir = await materializeRepo(entry, cacheDir, { spawn: deps.spawn });
    const findings = deps.scanFindings
      ? await deps.scanFindings(dir)
      : scanWithCli(dir, cli, spawn, root);
    const keys = findings.map((finding) => findingKey(finding)).sort();
    built[entry.name] = { sha: entry.sha ?? null, keys };
  }
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(buildSnapshot(built), null, 2)}\n`);
  return 0;
}

function isDirectRun() {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  return import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  runSnapshot(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    });
}
