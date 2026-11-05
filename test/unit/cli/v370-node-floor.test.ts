import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { nodeFloorMessage } from '../../../src/cli/node-floor.js';

const root = join(import.meta.dirname, '../../..');

describe('3.7.0 Node floor message', () => {
  it('names Node 22.13 for older runtimes and stays quiet on supported ones', () => {
    expect(nodeFloorMessage('22.12.9')).toMatch(/requires Node 22\.13 or newer/);
    expect(nodeFloorMessage('20.11.0')).toMatch(/requires Node 22\.13 or newer/);
    expect(nodeFloorMessage('22')).toMatch(/requires Node 22\.13 or newer/);
    expect(nodeFloorMessage('not-a-version')).toMatch(/requires Node 22\.13 or newer/);
    expect(nodeFloorMessage('22.13.0')).toBeUndefined();
    expect(nodeFloorMessage('24.1.0')).toBeUndefined();
  });

  it('checks the floor before the CLI parses, and does not link zlib.crc32 by name', () => {
    const cli = readFileSync(join(root, 'src/cli/index.ts'), 'utf8');
    const precision = readFileSync(join(root, 'src/modules/secrets/precision.ts'), 'utf8');
    expect(cli.indexOf('nodeFloorMessage')).toBeGreaterThan(-1);
    expect(cli.indexOf('nodeFloorMessage')).toBeLessThan(cli.indexOf('parseAsync'));
    expect(precision).not.toMatch(/import\s*\{[^}]*\bcrc32\b[^}]*\}\s*from\s*['"]node:zlib['"]/);
  });
});
