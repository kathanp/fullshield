#!/usr/bin/env node
// Opt-in. Add to package.json scripts.preinstall:
//   "preinstall": "node preinstall-guard.mjs"
// This process does not run the package being installed.
import { spawnSync } from 'node:child_process';

const spec = process.env.npm_package_name;
if (spec === undefined || spec.length === 0) {
  process.exit(0);
}
const result = spawnSync('fullshield', ['install', spec], { stdio: 'inherit' });
process.exit(result.status ?? 1);
