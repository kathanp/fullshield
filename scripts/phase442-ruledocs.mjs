#!/usr/bin/env node
/**
 * Phase 442. Static rule-doc generator.
 * Usage: node scripts/phase442-ruledocs.mjs <rulesDir> <outDir>
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const entry = join(root, 'src/phases/p442.ts');
const child = spawnSync(
  process.execPath,
  ['--experimental-strip-types', '--disable-warning=ExperimentalWarning', entry, ...process.argv.slice(2)],
  { stdio: 'inherit' },
);
process.exit(child.status === null ? 1 : child.status);
