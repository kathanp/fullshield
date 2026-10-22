import { describe, expect, it } from 'vitest';

import { ENV_CLIENT_RULE, FLAG, scanDefine, type PhaseFinding } from '../../../src/phases/p461.js';

const token = `AKIA${'Z'.repeat(16)}`;

describe('phase 461', () => {
  it('reports a client SECRET and redacts the value', () => {
    process.env[FLAG] = '1';
    process.env.LEAK_MARKER = 'leak-marker-unique';
    const findings = scanDefine('webpack.config.js', `module.exports = { target: 'web', define: { 'process.env.SECRET': '${token}' } };\n`);
    expect(findings.some((row) => row.ruleId === ENV_CLIENT_RULE && row.severity === 'high')).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(token);
    expect(JSON.stringify(findings)).not.toContain('leak-marker-unique');
  });

  it('ignores a public prefix and a server target', () => {
    process.env[FLAG] = '1';
    const pub = scanDefine('webpack.config.js', "module.exports = { target: 'web', define: { 'process.env.NEXT_PUBLIC_API': 'x' } };\n");
    expect(pub.some((row) => row.ruleId === ENV_CLIENT_RULE)).toBe(false);
    const server = scanDefine('webpack.config.js', "module.exports = { target: 'node', define: { 'process.env.SECRET': 'x' } };\n");
    expect(server.some((row) => row.ruleId === ENV_CLIENT_RULE)).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline: PhaseFinding[] = [{ ruleId: ENV_CLIENT_RULE, severity: 'high', file: 'webpack.config.js', line: 1, message: 'kept', snippet: '****' }];
    const text = "module.exports = { target: 'web', define: { 'process.env.SECRET': 'x' } };\n";
    expect(scanDefine('webpack.config.js', text, undefined, baseline)).toEqual(baseline);
  });
});
