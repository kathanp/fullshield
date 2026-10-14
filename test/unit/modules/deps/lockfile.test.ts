import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseLockfile, parseLockfileGraph } from '../../../../src/modules/deps/lockfile.js';

const fixtures = join(process.cwd(), 'test', 'fixtures', 'lockfiles');

function read(name: string): string {
  return readFileSync(join(fixtures, name), 'utf8');
}

describe('parseLockfile (npm package-lock v3)', () => {
  it('extracts name/version pairs including scoped and nested packages', () => {
    const packages = parseLockfile('package-lock.json', read('package-lock.json'));
    const keys = packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(keys).toEqual(['@scope/pkg@1.2.3', 'lodash@4.17.11', 'minimist@1.2.0']);
  });

  it('returns an empty list for a lockfile with no packages', () => {
    const packages = parseLockfile(
      'package-lock.json',
      JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x', version: '1.0.0' } } }),
    );
    expect(packages).toEqual([]);
  });
});

describe('parseLockfile (yarn classic)', () => {
  it('extracts name/version pairs including scoped packages and multi-range keys', () => {
    const packages = parseLockfile('yarn.lock', read('yarn.lock'));
    const keys = packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(keys).toEqual(['@scope/pkg@1.2.3', 'lodash@4.17.11', 'minimist@1.2.0']);
  });

  it('builds real dependency edges and marks them known', () => {
    const graph = parseLockfileGraph('yarn.lock', read('yarn.lock'));
    expect(graph.edgesKnown).toBe(true);
    expect([...graph.edges.get('lodash') ?? []]).toContain('minimist');
  });
});

describe('parseLockfile (pnpm)', () => {
  it('extracts name/version pairs, handling scoped names and peer suffixes', () => {
    const packages = parseLockfile('pnpm-lock.yaml', read('pnpm-lock.yaml'));
    const keys = packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(keys).toEqual(['@scope/pkg@1.2.3', 'lodash@4.17.11', 'minimist@1.2.0']);
  });

  it('builds real dependency edges from packages and importers', () => {
    const graph = parseLockfileGraph('pnpm-lock.yaml', read('pnpm-lock.yaml'));
    expect(graph.edgesKnown).toBe(true);
    expect(graph.directProd.has('lodash')).toBe(true);
    expect([...graph.edges.get('lodash') ?? []]).toContain('minimist');
  });
});

describe('parseLockfile (npm package-lock v2)', () => {
  it('prefers the packages table and preserves a deprecated notice', () => {
    const packages = parseLockfile('package-lock.json', read('package-lock-v2.json'));
    const keys = packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(keys).toEqual(['@scope/pkg@1.2.3', 'lodash@4.17.11', 'minimist@1.2.0']);
    const minimist = packages.find((p) => p.name === 'minimist');
    expect(minimist?.deprecated).toBe('this is a fixture deprecation notice');
  });

  it('walks the dependencies tree when the packages table is absent', () => {
    const packages = parseLockfile(
      'package-lock.json',
      JSON.stringify({
        lockfileVersion: 2,
        dependencies: {
          lodash: { version: '4.17.11' },
          '@scope/pkg': {
            version: '1.2.3',
            dependencies: { minimist: { version: '1.2.0' } },
          },
        },
      }),
    );
    const keys = packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(keys).toEqual(['@scope/pkg@1.2.3', 'lodash@4.17.11', 'minimist@1.2.0']);
  });
});

describe('parseLockfile (unknown)', () => {
  it('returns an empty list for unknown lockfile names', () => {
    const packages = parseLockfile('Cargo.lock', '');
    expect(packages).toEqual([]);
  });

  it('does not claim edges are known for an unrecognized lockfile', () => {
    const graph = parseLockfileGraph('Cargo.lock', '');
    expect(graph.edgesKnown).toBe(false);
    expect(graph.packages).toEqual([]);
  });
});

