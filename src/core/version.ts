import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the fullshield package version by walking up from this module
 * (works from both src/ during tests and dist/ in the built package).
 */
export function packageVersion(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      const raw = readFileSync(join(dir, 'package.json'), 'utf8');
      const pkg = JSON.parse(raw) as { name?: string; version?: string };
      if (pkg.name === 'fullshield' && typeof pkg.version === 'string') {
        return pkg.version;
      }
    } catch {
      // No package.json at this level; keep walking up.
    }
    const parent = dirname(dir);
    if (parent === dir) {break;}
    dir = parent;
  }
  throw new Error('fullshield package.json not found');
}
