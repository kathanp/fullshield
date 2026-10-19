import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { nodeOk } from '../../../src/cli/commands/doctor.js';

const root = join(import.meta.dirname, '../../..');

function declaredFloor(range: string): { major: number; minor: number } {
  const match = range.match(/>=\s*(\d+)\.(\d+)/);
  if (!match) {
    throw new Error(`engines range has no >= floor: ${range}`);
  }
  return { major: Number(match[1]), minor: Number(match[2]) };
}

describe('Phase 46 supported runtime', () => {
  it('rejects an engines floor below 22.13', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      engines: { node: string };
    };
    const floor = declaredFloor(pkg.engines.node);
    const highEnough = floor.major > 22 || (floor.major === 22 && floor.minor >= 13);
    expect(highEnough).toBe(true);
    expect(nodeOk('22.13.0')).toBe(true);
    expect(nodeOk('22.12.9')).toBe(false);
    expect(nodeOk('20.11.0')).toBe(false);
  });

  it('fails when the README version and package.json disagree', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const stated = readme.match(/\bv(\d+\.\d+\.\d+)\b/);
    expect(stated?.[1]).toBe(pkg.version);
  });

  it('does not list Node 20 in the CI matrix', () => {
    const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
    const matrix = ci.match(/node:\s*\[([^\]]+)\]/);
    expect(matrix?.[1]?.split(',').map((part) => part.trim())).toEqual(['22', '24']);
  });
});
