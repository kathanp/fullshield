import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, INSPECT_RULE, scanScripts } from '../../../src/phases/p463.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('phase 463', () => {
  it('rates bare --inspect high on start and medium on dev', () => {
    process.env[FLAG] = '1';
    const start = scanScripts({ start: 'node --inspect server.js' });
    expect(start.find((row) => row.ruleId === INSPECT_RULE)?.severity).toBe('high');
    expect(start[0]?.message).toContain('start');
    const dev = scanScripts({ dev: 'node --inspect server.js' });
    expect(dev.find((row) => row.ruleId === INSPECT_RULE)?.severity).toBe('medium');
  });

  it('ignores loopback inspect and --no-warnings', () => {
    process.env[FLAG] = '1';
    expect(scanScripts({ start: 'node --inspect=127.0.0.1 server.js' })).toEqual([]);
    expect(scanScripts({ start: 'node --no-warnings server.js' })).toEqual([]);
  });

  it('returns the baseline when the flag is off and does not spawn', () => {
    const baseline = [{ ruleId: 'kept', severity: 'high' as const, file: 'package.json', line: 1, message: 'kept' }];
    expect(scanScripts({ start: 'node --inspect server.js' }, baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p463.ts'), 'utf8');
    expect(src.includes('child_process')).toBe(false);
  });
});
