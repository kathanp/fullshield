import { describe, expect, it } from 'vitest';

import { FLAG, scanSourceMapConfig, SOURCEMAP_RULE, type PhaseFinding } from '../../../src/phases/p460.js';

describe('phase 460', () => {
  it('reports a top-level Next flag', () => {
    process.env[FLAG] = '1';
    const findings = scanSourceMapConfig('next.config.js', 'module.exports = { productionBrowserSourceMaps: true };\n');
    expect(findings.some((row) => row.ruleId === SOURCEMAP_RULE)).toBe(true);
    expect(findings[0]?.message).toContain('flag is set');
  });

  it('ignores a development-only flag and a server-only key', () => {
    process.env[FLAG] = '1';
    const dev = scanSourceMapConfig('next.config.js', "if (process.env.NODE_ENV !== 'production') {\n  module.exports = { productionBrowserSourceMaps: true };\n}\n");
    expect(dev.some((row) => row.ruleId === SOURCEMAP_RULE)).toBe(false);
    const server = scanSourceMapConfig('next.config.js', 'module.exports = { serverSourceMaps: true };\n');
    expect(server.some((row) => row.ruleId === SOURCEMAP_RULE)).toBe(false);
  });

  it('does not execute a config that calls process.exit', () => {
    process.env[FLAG] = '1';
    const before = process.exitCode;
    const findings = scanSourceMapConfig('next.config.js', 'process.exit(1);\nmodule.exports = { productionBrowserSourceMaps: true };\n');
    expect(process.exitCode).toBe(before);
    expect(findings.some((row) => row.ruleId === SOURCEMAP_RULE)).toBe(true);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline: PhaseFinding[] = [{ ruleId: SOURCEMAP_RULE, severity: 'low', file: 'next.config.js', line: 1, message: 'kept' }];
    expect(scanSourceMapConfig('next.config.js', 'module.exports = { productionBrowserSourceMaps: true };\n', baseline)).toEqual(baseline);
  });
});
