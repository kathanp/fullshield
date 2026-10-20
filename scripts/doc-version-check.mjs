#!/usr/bin/env node
// Fails when a doc names a FullShield version as current that is not package.json version.
// Skips CHANGELOG.md and docs/history/. Not packed.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

function argRoot() {
  const index = process.argv.indexOf('--root');
  if (index !== -1 && process.argv[index + 1]) return process.argv[index + 1];
  return process.cwd();
}

const root = argRoot();
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const skip = new Set(['node_modules', '.git', 'dist', 'coverage', 'bench', 'reports']);
const files = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (skip.has(name)) continue;
    const p = join(dir, name);
    const rel = relative(root, p).split('\\').join('/');
    if (rel.startsWith('docs/history/')) continue;
    if (statSync(p).isDirectory()) walk(p);
    else if (name.endsWith('.md') && rel !== 'CHANGELOG.md') files.push(p);
  }
}
walk(root);

// Phrases that claim a version is current.
const patterns = [
  /FullShield v(\d+\.\d+\.\d+)/g,
  /\*\*v(\d+\.\d+\.\d+)\*\*/g,
  /This tree is (\d+\.\d+\.\d+)/g,
  /FullShield version: (\d+\.\d+\.\d+)/g,
  /\bv(\d+\.\d+\.\d+)\s*\/\s*alpha/g,
];

const bad = [];
for (const f of files) {
  const lines = readFileSync(f, 'utf8').split(/\r?\n/);
  lines.forEach((line, i) => {
    for (const re of patterns) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) {
        if (m[1] !== version) bad.push(`${relative(root, f)}:${i + 1}: ${m[0]} (package.json is ${version})`);
      }
    }
  });
}

if (bad.length) {
  console.error('doc-version-check: docs name a different current version:\n' + bad.join('\n'));
  process.exit(1);
}
console.log(`doc-version-check: ok (${files.length} files, version ${version})`);
