import { describe, expect, it } from 'vitest';

import * as fullshield from '../../src/index.js';

describe('public API surface', () => {
  it('exports the library entry points', () => {
    expect(typeof fullshield.scan).toBe('function');
    expect(typeof fullshield.runScan).toBe('function');
    expect(typeof fullshield.loadConfig).toBe('function');
    expect(typeof fullshield.walkFiles).toBe('function');
    expect(typeof fullshield.renderConsoleReport).toBe('function');
    expect(typeof fullshield.renderJsonReport).toBe('function');
    expect(typeof fullshield.makeFindingId).toBe('function');
    expect(typeof fullshield.meetsThreshold).toBe('function');
    expect(typeof fullshield.packageVersion).toBe('function');
  });

  it('exports severity/module constants and the phase-1 module registry', () => {
    expect(fullshield.SEVERITIES).toEqual(['info', 'low', 'medium', 'high', 'critical']);
    expect(fullshield.MODULE_NAMES).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(fullshield.builtinModules).toEqual([]);
    expect(fullshield.IMPLEMENTED_MODULES).toEqual([]);
    expect(fullshield.DEFAULT_CONFIG.failOn).toBe('high');
  });
});
