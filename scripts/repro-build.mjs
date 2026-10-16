#!/usr/bin/env node
/** Build twice and compare dist file hashes. Prints differing paths. */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function hashTree(dir, out = new Map()) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) hashTree(full, out);
    else out.set(full.slice(root.length + 1), createHash('sha256').update(readFileSync(full)).digest('hex'));
  }
  return out;
}

function build() {
  const result = spawnSync('npm', ['run', 'build'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) {
    console.error(result.stderr);
    process.exit(2);
  }
}

if (process.argv.includes('--check')) {
  build();
  const first = hashTree(join(root, 'dist'));
  build();
  const second = hashTree(join(root, 'dist'));
  const keys = new Set([...first.keys(), ...second.keys()]);
  const differ = [];
  for (const key of keys) {
    if (first.get(key) !== second.get(key)) differ.push(key);
  }
  if (differ.length > 0) {
    console.error(`nondeterministic dist files:\n${differ.join('\n')}`);
    process.exit(1);
  }
  console.log(`reproducible: ${first.size} dist files hashed the same across two builds`);
} else {
  console.log('pass --check to build twice and compare dist hashes');
}
