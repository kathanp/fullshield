import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

function vulnerable(version: string): boolean {
  const [major = 0, minor = 0, patch = 0] = version.split('.').map((part) => Number(part));
  const below = major < 1 || (major === 1 && (minor < 20 || (minor === 20 && patch < 9)));
  const v2 = major === 2 && minor < 4;
  return below || v2;
}

function bodyParserVersions(lock: { packages?: Record<string, { version?: string }> }): string[] {
  const packages = lock.packages ?? {};
  const versions: string[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (key === 'node_modules/body-parser' || key.endsWith('/node_modules/body-parser')) {
      if (typeof entry.version === 'string') {versions.push(entry.version);}
    }
  }
  return versions.sort();
}

describe('phase 531 body-parser dev install', () => {
  it('resolves every body-parser copy outside GHSA-27r3-jxmh-p828', () => {
    const lock = JSON.parse(readFileSync(join(process.cwd(), 'package-lock.json'), 'utf8')) as {
      packages?: Record<string, { version?: string }>;
    };
    const versions = bodyParserVersions(lock);
    expect(versions.length).toBeGreaterThan(0);
    expect(versions.filter(vulnerable)).toEqual([]);
  });

  it('does not add an overrides entry', () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as { overrides?: unknown };
    expect(pkg.overrides).toBeUndefined();
  });
});
