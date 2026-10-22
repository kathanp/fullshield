import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p356.js';
import { FLAG as SCRIPT } from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 356', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.scriptHosts("fetch('https://downloads.example.invalid/a')", 'preinstall')).toEqual([]);
  });

  it('reports an unlisted host and allows the registry host', () => {
    process.env[phase.FLAG] = '1';
    process.env[SCRIPT] = '1';
    const hit = phase.scriptHosts('fetch("https://downloads.example.invalid/a")', 'preinstall');
    expect(hit[0]?.host).toBe('downloads.example.invalid');
    expect(phase.scriptHosts('fetch("https://registry.npmjs.org/left")', 'preinstall')).toEqual([]);
    expect(phase.scriptHosts('console.log("https://downloads.example.invalid/a")', 'preinstall')).toEqual([]);
    delete process.env[SCRIPT];
  });
});
