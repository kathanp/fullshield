import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { dryRun, enabled, FLAG } from '../../../src/phases/p406.js';

const source = 'const a = 1;\n// keep me\n';
const edit = { fingerprint: 'fp', witnessId: 'w1', start: 6, end: 7, replacement: 'b' };

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 406', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(dryRun(source, edit, false).applied).toBe(false);
  });

  it('refuses a broken edit, a dirty tree, and keeps an untouched comment', () => {
    process.env[FLAG] = '1';
    const broken = dryRun(source, { ...edit, replacement: 'const (' }, false);
    expect(broken.applied).toBe(false);
    expect(broken.source).toBe(source);
    expect(dryRun(source, edit, true).applied).toBe(false);
    const clean = dryRun(source, edit, false);
    expect(clean.applied).toBe(true);
    expect(clean.source.endsWith('// keep me\n')).toBe(true);
    expect(clean.diff.startsWith('-a\n+b')).toBe(true);
    expect(clean.witnessId).toBe('w1');
    const file = readFileSync(new URL('../../../src/phases/p406.ts', import.meta.url), 'utf8');
    expect(file.includes('git push')).toBe(false);
  });
});
