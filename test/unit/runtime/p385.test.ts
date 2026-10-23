import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { cmdHole, commandEvent, enabled, FLAG, posixHole } from '../../../src/runtime/exp/p385.js';

describe('phase 385 cmd tokenizer', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(commandEvent({ program: 'cmd.exe', shell: true, args: ['/c', '%PATH%'] })).toBe(false);
  });

  it('treats percent as a cmd event and not as a POSIX event', () => {
    process.env[FLAG] = '1';
    expect(cmdHole('%PATH%')).toBe(true);
    expect(posixHole('%PATH%')).toBe(false);
    expect(commandEvent({ program: 'cmd.exe', shell: true, args: ['/c', '%PATH%'] })).toBe(true);
  });

  it('does not flag execFile arguments that contain percent', () => {
    process.env[FLAG] = '1';
    expect(commandEvent({ program: 'execFile', shell: false, args: ['tool', '100%'] })).toBe(false);
    expect(commandEvent({ program: 'node', shell: false, args: [] })).toBe(false);
    expect(commandEvent({ program: 'node', shell: false, args: ['app;id'] })).toBe(true);
    expect(commandEvent({ program: 'cmd.exe', shell: false, args: ['/c'] })).toBe(false);
    expect(commandEvent({ program: 'cmd.exe', shell: false, args: ['/c', '&'] })).toBe(true);
    expect(commandEvent({ program: 'execFile', shell: true, args: ['100%'] })).toBe(true);
    expect(commandEvent({ program: 'sh', shell: false, args: ['-c', 'plain'] })).toBe(false);
  });

  it('does not spawn a process', () => {
    const source = readFileSync(new URL('../../../src/runtime/exp/p385.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('child_process');
    expect(source).not.toContain('node:sqlite');
  });
});
