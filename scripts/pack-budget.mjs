#!/usr/bin/env node
/**
 * Phase 36. Fail if the npm pack is over 3.0 MB unpacked, over 320 files,
 * or adds a hard dependency versus the last v* tag.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { baselineTag, packBudgetErrors, packReportEntry, parseLeadingJson } from './release-checks.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';

function gitShow(rev, path) {
  const result = spawnSync('git', ['show', `${rev}:${path}`], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) return null;
  return result.stdout;
}

function hardDeps(pkg) {
  return Object.keys(pkg.dependencies ?? {}).sort();
}

function main() {
  const packed = spawnSync(isWindows ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
    shell: isWindows,
  });
  if (packed.status !== 0) {
    console.error(packed.stderr || packed.stdout);
    process.exit(2);
  }
  const entry = packReportEntry(parseLeadingJson(packed.stdout));
  const tags = spawnSync('git', ['tag', '--list', 'v*', '--sort=-v:refname'], {
    cwd: root,
    encoding: 'utf8',
  }).stdout.trim().split('\n').filter(Boolean);
  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim();
  let previousTag = '';
  try {
    previousTag = baselineTag(tags, head, (tag) =>
      spawnSync('git', ['rev-parse', `${tag}^{}`], { cwd: root, encoding: 'utf8' }).stdout.trim(),
    );
  } catch {
    previousTag = '';
  }
  const previous = previousTag !== '' ? gitShow(previousTag, 'package.json') : null;
  const previousDeps = previous ? hardDeps(JSON.parse(previous)) : hardDeps(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')));
  const current = hardDeps(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')));
  const unpackedBytes = entry.unpackedSize ?? 0;
  const fileCount = Array.isArray(entry.files) ? entry.files.length : 0;
  const errors = packBudgetErrors({
    unpackedBytes,
    fileCount,
    hardDeps: current,
    previousHardDeps: previousDeps,
  });
  console.log(`pack-budget unpacked=${unpackedBytes} files=${fileCount} hardDeps=${current.length}`);
  if (errors.length > 0) {
    for (const error of errors) console.error(`pack-budget: ${error}`);
    process.exit(1);
  }
  console.log('pack-budget ok');
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
}
