import { describe, expect, it } from 'vitest';

import { analyzeShell, enabled, FLAG } from '../../../src/phases/p280.js';

describe('phase 280 shell context', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeShell("function f(req) { exec('echo ' + req.query.x); }").findings).toEqual([]);
  });

  it('classifies single quotes, double quotes, and bare words', () => {
    process.env[FLAG] = '1';
    const bare = analyzeShell("function f(req) { exec('echo ' + req.query.x); }");
    const double = analyzeShell('function f(req) { exec(\'echo "\' + req.query.x + \'"\'); }');
    const single = analyzeShell('function f(req) { exec("echo \'" + req.query.x + "\'"); }');
    expect(bare.findings[0]?.shellContext).toBe('bare');
    expect(double.findings[0]?.shellContext).toBe('double');
    expect(single.findings[0]?.shellContext).toBe('single');
    expect(bare.findings[0]?.ruleId).toBe('SAST-CMDI-001');
  });

  it('reports execFile option injection unless -- precedes the value', () => {
    process.env[FLAG] = '1';
    const open = analyzeShell("function f(userRef) { execFile('git', ['log', userRef]); }");
    const closed = analyzeShell("function f(userRef) { execFile('git', ['log', '--', userRef]); }");
    expect(open.findings).toEqual([
      expect.objectContaining({ ruleId: 'SAST-CMDI-001', shellContext: 'option' }),
    ]);
    expect(closed.findings).toEqual([]);
  });

  it('classifies spawn, numeric options, and quoted holes', () => {
    process.env[FLAG] = '1';
    expect(analyzeShell(':::').findings).toEqual([]);
    const source = [
      'function f(req) {',
      '  if (cond) exec(req.query.x); else execSync(req.query.x);',
      '  spawn("cmd", ["-" + user], { shell: true });',
      '  spawn("cmd", [Number(req.query.x)]);',
      '  execFile("git", ["log", ...rest, null, "--", user]);',
      '  const n = Number(req.query.x);',
      '  exec("echo " + n);',
      '  exec(...args);',
      '}',
    ].join('\n');
    const result = analyzeShell(source);
    expect(result.findings.length).toBeGreaterThan(0);
    delete process.env[FLAG];
  });
});
