import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { applyCodemod, dryRun, enabled, findNodeRange, FLAG, type CodeEdit } from '../../../src/phases/p406.js';

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

  it('finds a range and applies a codemod only when the engine is on and the tree is clean', () => {
    const edit: CodeEdit = { ...{ fingerprint: 'fp', witnessId: 'w1', start: 6, end: 7, replacement: 'b' }, disposition: 'safe', ruleId: 'R', directory: 'src' };
    expect(findNodeRange(source, 'const')).toEqual({ start: 0, end: 5 });
    expect(findNodeRange(source, 'missing')).toBeNull();
    expect(applyCodemod(source, [edit], false, 'apply')).toEqual({ source, edits: [], reason: 'engine off' });
    process.env[FLAG] = '1';
    expect(applyCodemod(source, [edit], true, 'apply').reason).toBe('dirty');
    expect(applyCodemod(source, [{ ...edit, replacement: 'const (' }], false, 'apply').reason).toBe('re-parse failed');
    const dry = applyCodemod(source, [edit], false, 'dry-run');
    expect(dry.reason).toBe('dry-run');
    expect(dry.source).toContain('const b = 1;');
    const applied = applyCodemod(source, [edit, { ...edit, start: 10, end: 11, replacement: '2' }], false, 'apply');
    expect(applied.reason).toBe('');
    expect(applied.edits).toHaveLength(2);
    expect(applied.source).toContain('const b = 2;');
    expect(applyCodemod(source, [], false, 'dry-run')).toEqual({ source, edits: [], reason: 'dry-run' });
    expect(applyCodemod(source, [], false, 'apply').reason).toBe('');
    delete process.env[FLAG];
  });
});
