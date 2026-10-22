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
});
