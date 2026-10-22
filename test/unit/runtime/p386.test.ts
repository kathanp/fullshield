import { describe, expect, it } from 'vitest';

import { enabled, FLAG, hookRejects, staticWindowsPath } from '../../../src/runtime/exp/p386.js';

describe('phase 386 windows paths', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(staticWindowsPath('\\\\server\\share', true, false)).toBeNull();
  });

  it('reports a tainted UNC segment and says it is a Windows path', () => {
    process.env[FLAG] = '1';
    const finding = staticWindowsPath('\\\\server\\share', true, false);
    expect(finding?.ruleId).toBe('SAST-PATH-001');
    expect(finding?.message).toContain('Windows path');
  });

  it('clears the form after basename and allows a child of a UNC base', () => {
    process.env[FLAG] = '1';
    expect(staticWindowsPath('\\\\server\\share', true, true)).toBeNull();
    expect(hookRejects('\\\\server\\share', '\\\\server\\share\\child', 'win32')).toBe(false);
    expect(hookRejects('C:\\data', '\\\\other\\share', 'win32')).toBe(true);
    expect(hookRejects('C:\\data', '\\\\other\\share', 'posix')).toBe(false);
  });
});
