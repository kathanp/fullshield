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

  it('classifies medium names, public formats, spreads, and a config that does not parse', () => {
    process.env[FLAG] = '1';
    const formats = [{ id: 'pub', pattern: /PUB_/, publicByDesign: true }];
    try {
      const medium = scanDefine('webpack.config.js', "module.exports = { target: 'web', define: { 'process.env.LOG_LEVEL': 'info', SECRET: 'x', ...extra } };\n");
      expect(medium.some((row) => row.severity === 'medium' && row.message.includes('LOG_LEVEL'))).toBe(true);
      expect(medium.some((row) => row.severity === 'high' && row.message.includes('SECRET'))).toBe(true);
      const suffix = scanDefine('webpack.config.js', "module.exports = { target: 'browser', define: { 'process.env.DB_PASSWORD': 'x', 'process.env.AWS_ACCESS_KEY_ID': 'x' } };\n");
      expect(suffix.filter((row) => row.severity === 'high')).toHaveLength(2);
      expect(scanDefine('webpack.config.js', "module.exports = { target: 'web', define: { 'process.env.PUBLIC_TOKEN': 'x' } };\n", [{ id: 'pub', pattern: /PUBLIC_TOKEN/, publicByDesign: true }])).toEqual([]);
      expect(scanDefine('webpack.config.js', "module.exports = { target: 'web', define: { 'process.env.SECRET': 'PUB_ABCD' } };\n", formats)).toEqual([]);
      expect(scanDefine('webpack.config.js', "module.exports = { target: 'web', define: { 'process.env.VITE_TOKEN': 'x', 1: 'x', 'process.env.VITE_COUNT': 2 } };\n")).toEqual([]);
      expect(scanDefine('webpack.config.js', "module.exports = { define: { 'process.env.LOG_LEVEL': 'info' } };\n")).toEqual([]);
      const loose = scanDefine('webpack.config.js', "module.exports = { target: name, define: 'nope', env: { OK: true } };\n");
      expect(loose.some((row) => row.message.includes('OK'))).toBe(true);
      const baseline: PhaseFinding[] = [{ ruleId: ENV_CLIENT_RULE, severity: 'high', file: 'webpack.config.js', line: 1, message: 'kept', snippet: '****' }];
      expect(scanDefine('webpack.config.js', 'const =', undefined, baseline)).toEqual(baseline);
      const named = scanDefine('vite.config.js', "export default { env: { 'process.env.LOG_LEVEL': 'info' } };\n");
      expect(named.some((row) => row.severity === 'medium')).toBe(true);
    } finally {
      delete process.env[FLAG];
      delete process.env.LEAK_MARKER;
    }
  });
});
