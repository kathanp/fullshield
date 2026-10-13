import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

import ignoreModule from 'ignore';

// `ignore` is CJS; under NodeNext the typed default import is the module
// namespace. The runtime object exposes the factory both as itself and as
// `.default` (verified), so `.default` is correct in Node ESM and in Vitest.
const ignoreFactory = ignoreModule.default;

export interface WalkOptions {
  cwd: string;
  /** Extra gitignore-style patterns (from config) on top of .gitignore. */
  ignore?: string[];
}

/** Always ignored regardless of .gitignore/config. */
const ALWAYS_IGNORED = ['.git/', 'node_modules/'];

/**
 * Recursively list files under `cwd`, respecting the project's .gitignore and
 * the config `ignore` globs. Returns sorted, posix-style relative paths.
 * Symlinks are never followed (a scanner must not escape the scan root).
 */
export async function walkFiles(options: WalkOptions): Promise<string[]> {
  const ig = ignoreFactory();
  ig.add(ALWAYS_IGNORED);
  try {
    ig.add(await readFile(join(options.cwd, '.gitignore'), 'utf8'));
  } catch {
    // No .gitignore at the scan root; nothing to add.
  }
  ig.add(options.ignore ?? []);

  const files: string[] = [];

  async function walk(relDir: string): Promise<void> {
    const entries = await readdir(join(options.cwd, relDir), { withFileTypes: true });
    for (const entry of entries) {
      const rel = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!ig.ignores(`${rel}/`)) {
          await walk(rel);
        }
      } else if (entry.isFile()) {
        if (!ig.ignores(rel)) {
          files.push(rel);
        }
      }
    }
  }

  await walk('');
  return files.sort();
}
