import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, initOutput, PRECOMMIT_COMMAND, renderHook, type HookKind } from '../../../src/phases/p438.js';

afterEach(() => {
  delete process.env[FLAG];
});

const kinds: HookKind[] = ['husky', 'lefthook', 'pre-commit'];

describe('phase 438 hook templates', () => {
  it('returns the init text unchanged when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(initOutput('keep-me')).toBe('keep-me');
    for (const kind of kinds) {
      expect(renderHook(kind)).toBeNull();
    }
  });

  it('renders local hook text that runs the precommit command', () => {
    process.env[FLAG] = '1';
    const husky = renderHook('husky');
    expect(husky).toContain(PRECOMMIT_COMMAND);
    expect(husky).toContain('not the full scan');
    expect(renderHook('lefthook')).toContain('fullshield:');
    expect(renderHook('pre-commit')).toContain('language: system');
    for (const kind of kinds) {
      const text = renderHook(kind) ?? '';
      expect(text).toContain(PRECOMMIT_COMMAND);
      expect(text).not.toContain('git config');
      expect(text).not.toContain('curl');
    }
    expect(initOutput('keep-me')).toBe(`keep-me\n${husky ?? ''}`);
  });

  it('appends the husky template instead of replacing init text', () => {
    process.env[FLAG] = '1';
    const text = initOutput('existing hook');
    expect(text.startsWith('existing hook\n')).toBe(true);
    expect(text).not.toContain('fullshield scan');
  });
});
