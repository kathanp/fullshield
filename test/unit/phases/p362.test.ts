import { describe, expect, it } from 'vitest';

import { enabled, FLAG, timeGates } from '../../../src/phases/p362.js';

describe('phase 362 time and locale gates', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(timeGates('pkg', 'if (new Date().getUTCFullYear() > 2020) fetch("https://example.invalid")')).toEqual([]);
  });

  it('reports a date condition that dominates fetch', () => {
    process.env[FLAG] = '1';
    const findings = timeGates('pkg', 'if (new Date().getUTCFullYear() > 2020) fetch("https://example.invalid")');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('DEPS-TIMEGATE-001');
    expect(findings[0]?.condition).toBe('Date');
    expect(findings[0]?.sinkClass).toBe('net');
    expect(findings[0]?.message.toLowerCase()).not.toContain('protestware');
  });

  it('does not report a date condition around console.log', () => {
    process.env[FLAG] = '1';
    expect(timeGates('pkg', 'if (new Date().getUTCFullYear() > 2020) console.log("hi")')).toEqual([]);
  });

  it('reports a locale check that exits the process', () => {
    process.env[FLAG] = '1';
    const findings = timeGates('pkg', 'if (process.env.LANG === "C") process.exit(1)');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.sinkClass).toBe('process-exit');
    expect(findings[0]?.condition).toBe('process.env.LANG');
  });

  it('does not report a process.version check', () => {
    process.env[FLAG] = '1';
    expect(timeGates('pkg', 'if (process.version.startsWith("v18")) process.exit(1)')).toEqual([]);
  });

  it('does not report a script with no date API', () => {
    process.env[FLAG] = '1';
    expect(timeGates('pkg', 'fetch("https://example.invalid")')).toEqual([]);
  });

  it('reports filesystem and shell sinks, locale and Intl conditions, and ignores a broken script', () => {
    process.env[FLAG] = '1';
    const write = timeGates('pkg', 'if (Date.now() > 0) fs.writeFileSync("a", "b")');
    expect(write[0]?.sinkClass).toBe('fs-write');
    expect(write[0]?.condition).toBe('Date');
    const shell = timeGates('pkg', 'if (new Date() > 0) child.execSync("ls")');
    expect(shell[0]?.sinkClass).toBe('shell');
    const tz = timeGates('pkg', 'if (process.env.TZ === "UTC") fetch("https://example.invalid")');
    expect(tz[0]?.condition).toBe('process.env.TZ');
    const intl = timeGates('pkg', 'if (Intl) fetch("https://example.invalid")');
    expect(intl[0]?.condition).toBe('Intl');
    const member = timeGates('pkg', 'if (Intl.DateTimeFormat) fetch("https://example.invalid")');
    expect(member[0]?.condition).toBe('Intl');
    const alternate = timeGates('pkg', 'if (new Date() > 0) { const x = 1; } else { fs.appendFileSync("a", "b"); }');
    expect(alternate[0]?.sinkClass).toBe('fs-write');
    const both = timeGates('pkg', 'if (new Date() > 0) fetch("https://example.invalid");\nif (new Date() > 0) fs.writeFileSync("a", "b");');
    expect(both).toHaveLength(1);
    expect(both[0]?.sinkClass).toBe('net');
    expect(timeGates('pkg', 'if (new Date() > 0) obj["fetch"]("https://example.invalid")')).toEqual([]);
    expect(timeGates('pkg', 'if (a[b].c) fetch("https://example.invalid")')).toEqual([]);
    expect(timeGates('pkg', 'if (')).toEqual([]);
    delete process.env[FLAG];
  });
});
