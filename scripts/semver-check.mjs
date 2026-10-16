#!/usr/bin/env node
/**
 * Phase 36. HEAD vs the last v* tag.
 * New rule IDs, commands, flags, exports, or a stable-output snapshot diff
 * require a minor bump. Otherwise a patch. Exit 1 if package.json is smaller.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpKind, bumpSatisfies, requiredBump } from './release-checks.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function git(args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function show(rev, path) {
  const result = spawnSync('git', ['show', `${rev}:${path}`], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) return '';
  return result.stdout;
}

function ruleIdsFromTree(rev) {
  const list = git(['ls-tree', '-r', '--name-only', rev, 'rules']).trim();
  if (list === '') return [];
  return list
    .split('\n')
    .map((path) => path.replace(/^rules\//, '').replace(/\.md$/, ''))
    .filter((id) => id !== 'README' && id.includes('-'));
}

function addedMatches(rev, path, pattern) {
  const diff = git(['diff', '-U0', rev, 'HEAD', '--', path]);
  const found = [];
  for (const line of diff.split('\n')) {
    if (!line.startsWith('+') || line.startsWith('+++')) continue;
    const match = line.match(pattern);
    if (match?.[1]) found.push(match[1]);
  }
  return found;
}

function exportKeys(source) {
  try {
    const pkg = JSON.parse(source);
    return Object.keys(pkg.exports ?? {});
  } catch {
    return [];
  }
}

function stableChanged(fromVersion) {
  const snap = join(root, 'bench', 'snapshots', `${fromVersion}.json`);
  const headSnap = join(root, 'bench', 'snapshots', 'HEAD.json');
  if (!existsSync(snap) || !existsSync(headSnap)) return false;
  const base = JSON.parse(readFileSync(snap, 'utf8'));
  const head = JSON.parse(readFileSync(headSnap, 'utf8'));
  return JSON.stringify(base.apps ?? null) !== JSON.stringify(head.apps ?? null);
}

function main() {
  const tags = git(['tag', '--list', 'v*', '--sort=-v:refname']).trim().split('\n').filter(Boolean);
  if (tags.length === 0) throw new Error('no v* tag to compare');
  const tag = tags[0];
  const fromPkg = JSON.parse(show(tag, 'package.json'));
  const toPkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const fromIds = new Set(ruleIdsFromTree(tag));
  const toIds = ruleIdsFromTree('HEAD');
  const signals = {
    newRuleIds: toIds.filter((id) => !fromIds.has(id)),
    newCommands: addedMatches(tag, 'src/cli/program.ts', /\.command\(\s*['"]([^'"]+)['"]/),
    newFlags: addedMatches(tag, 'src/cli/program.ts', /\.option\(\s*['"](--[^'"]+)['"]/),
    newExports: exportKeys(readFileSync(join(root, 'package.json'), 'utf8')).filter(
      (key) => !exportKeys(show(tag, 'package.json')).includes(key),
    ),
    stableChanged: stableChanged(fromPkg.version),
  };
  const required = requiredBump(signals);
  const actual = bumpKind(fromPkg.version, toPkg.version);
  console.log(`semver-check last tag ${tag} (${fromPkg.version}) -> ${toPkg.version}`);
  console.log(`required: ${required}`);
  console.log(`actual: ${actual}`);
  for (const [name, values] of Object.entries(signals)) {
    if (name === 'stableChanged') {
      console.log(`stableChanged: ${values}`);
      continue;
    }
    if (values.length > 0) console.log(`${name}: ${values.join(', ')}`);
  }
  if (!bumpSatisfies(actual, required)) {
    console.error(`package.json bump ${actual} is smaller than required ${required}`);
    process.exit(1);
  }
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
}
