import { afterEach, describe, expect, it } from 'vitest';

import { parseLockfileGraph } from '../../../../src/modules/deps/lockfile.js';

const yarnBerry = `
__metadata:
  version: 6

"pad-left@npm:1.2.0":
  version: 1.2.0

"left-pad@npm:1.0.0":
  version: 1.0.0
  dependencies:
    pad-left: "npm:1.2.0"

"app@workspace:.":
  dependencies:
    left-pad: "npm:1.0.0"
`;

const pnpmV9 = `
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.0.0
        version: 1.0.0

packages:
  left-pad@1.0.0:
    resolution: {integrity: sha512-abc}

  pad-left@1.2.0:
    resolution: {integrity: sha512-def}

snapshots:
  left-pad@1.0.0:
    dependencies:
      pad-left: 1.2.0

  pad-left@1.2.0: {}
`;

const bun = `{
  "packages": {
    "left-pad": ["left-pad@1.0.0", { "dependencies": { "pad-left": "1.2.0" } }],
    "pad-left": ["pad-left@1.2.0", {}]
  }
}`;

describe('phase 63 modern lockfiles', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_LOCKFILES;
  });

  it('keeps today\'s yarn parser when the flag is off', () => {
    const graph = parseLockfileGraph('yarn.lock', yarnBerry);
    expect(graph.edgesKnown).toBe(true);
    expect(graph.packages.some((pkg) => pkg.version.includes('__metadata'))).toBe(false);
  });

  it('reads yarn berry, pnpm v9, and bun.lock edges when the flag is on', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_LOCKFILES = '1';
    const yarn = parseLockfileGraph('yarn.lock', yarnBerry);
    expect(yarn.directProd.has('left-pad')).toBe(true);
    expect(yarn.edges.get('left-pad')?.has('pad-left')).toBe(true);
    expect(yarn.packages.find((pkg) => pkg.name === 'left-pad')?.version).toBe('1.0.0');
    const pnpm = parseLockfileGraph('pnpm-lock.yaml', pnpmV9);
    expect(pnpm.directProd.has('left-pad')).toBe(true);
    expect(pnpm.edges.get('left-pad')?.has('pad-left')).toBe(true);
    const bunGraph = parseLockfileGraph('bun.lock', bun);
    expect(bunGraph.edges.get('left-pad')?.has('pad-left')).toBe(true);
    expect(bunGraph.edgesKnown).toBe(true);
  });
});
