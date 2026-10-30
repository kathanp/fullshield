import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { summarize, type Finding, type Severity } from '../../../src/core/finding.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderMarkdownReport } from '../../../src/reporters/markdown.js';

function finding(partial: Partial<Finding> & Pick<Finding, 'id' | 'ruleId' | 'severity'>): Finding {
  return {
    module: 'sast',
    title: 'SQL injection',
    confidence: 'high',
    file: 'src/a.js',
    line: 1,
    message: 'tainted',
    remediation: 'Use a parameterized query.',
    ...partial,
  };
}

function result(findings: Finding[], failOn: Severity = 'high'): ScanResult {
  const built: ScanResult = {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '3.5.3',
      startedAt: '2026-10-30T00:00:00.000Z',
      durationMs: 4,
      cwd: '/tmp/app',
      filesScanned: 3,
      modulesRequested: ['deps', 'secrets', 'sast'],
      modulesRun: ['deps', 'secrets', 'sast'],
      upgradePlan: {
        bumps: [{ name: 'lodash', from: '4.17.11', to: '4.17.21', safe: true, findings: 1 }],
        unresolved: [],
        sentence: '1 dependency has a fixed version.',
      },
      unusedDirect: { packages: ['left-pad', 'moment'], advisories: 2 },
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
  built.config.failOn = failOn;
  return built;
}

describe('phase 574 report', () => {
  const malicious = finding({
    id: 'mal',
    ruleId: 'DEPS-MALICIOUS-001',
    module: 'deps',
    severity: 'critical',
    snippet: 'evil-pack@1.0.0',
    title: 'malicious package',
    remediation: 'Remove it.',
  });
  const bump = finding({
    id: 'bump',
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    severity: 'high',
    reachability: 'reachable',
    snippet: 'lodash@4.17.11',
    title: 'vulnerable dependency',
    remediation: 'Upgrade.',
  });
  const secret = finding({
    id: 'sec',
    ruleId: 'SECRET-AWS-001',
    module: 'secrets',
    severity: 'high',
    file: 'src/keys.js',
    line: 4,
    title: 'AWS key',
    remediation: 'Rotate this credential and store it outside the repo.',
  });
  const sqliA = finding({
    id: 'a',
    ruleId: 'SAST-SQLI-001',
    file: 'src/a.js',
    line: 2,
    severity: 'high',
    title: 'SQL injection',
    remediation: 'SQL injection. See https://cwe.mitre.org/data/definitions/89.html',
  });
  const sqliB = finding({
    id: 'b',
    ruleId: 'SAST-SQLI-001',
    file: 'src/b.js',
    line: 9,
    severity: 'high',
    title: 'SQL injection',
    remediation: 'SQL injection. See https://cwe.mitre.org/data/definitions/89.html',
  });

  it('uses one total, a fail line, three first actions, and one rule group', () => {
    const text = renderConsoleReport(result([malicious, bump, secret, sqliA, sqliB]));
    expect(text).toContain('5 findings: 1 critical, 4 high');
    expect(text).toContain('fail (failOn high, 5 at or above)');
    expect(text).toContain('✖ 5 finding(s): 1 critical, 4 high');
    expect(text).toContain('HIGH (4)');
    expect(text.indexOf('Do this first')).toBeLessThan(text.indexOf('HIGH (4)'));
    expect(text).toContain('1. Remove evil-pack@1.0.0. It is flagged malicious. Reinstall and rotate credentials.');
    expect(text).toContain('2. Upgrade lodash 4.17.11 → 4.17.21.');
    expect(text).toContain('3. Rotate the secret at src/keys.js:4.');
    expect(text).toContain('1 dependency has a fixed version.');
    expect(text).toContain('2 packages are never imported; removing them clears 2 advisories.');
    expect(text.indexOf('Do this first')).toBeLessThan(text.indexOf('1 dependency has a fixed version.'));
    expect(text.split('\n').filter((line) => line.includes('[SAST-SQLI-001]'))).toHaveLength(1);
    expect(text).toContain('× 2');
    expect(text).toContain('src/a.js:2');
    expect(text).toContain('src/b.js:9');
    expect(text).toContain('Rotate it, then load it from the environment.');
    expect(text).toContain('Change the flagged call. The docs line names the rule.');
    expect(text).toContain('docs: rules/SAST-SQLI-001.md https://cwe.mitre.org/data/definitions/89.html');
  });

  it('says pass when nothing meets failOn and keeps --all as one line per finding', () => {
    const info = finding({ id: 'info', ruleId: 'CONFIG-SCRIPTS-001', module: 'config', severity: 'info', confidence: 'medium' });
    const text = renderConsoleReport(result([info], 'high'));
    expect(text).toContain('pass');
    expect(text).not.toContain('fail (failOn');
    const all = renderConsoleReport(result([sqliA, sqliB]), { all: true });
    expect(all.match(/\[SAST-SQLI-001\]/g)).toHaveLength(2);
    expect(all).toContain('(src/a.js:2)');
    expect(all).toContain('(src/b.js:9)');
  });

  it('writes the same opening in markdown and keeps every location under one heading', () => {
    const md = renderMarkdownReport(result([malicious, bump, secret, sqliA, sqliB]));
    expect(md).toContain('**5 findings: 1 critical, 4 high.**');
    expect(md).toContain('Fail: failOn is high.');
    expect(md).toContain('## Do this first');
    expect(md).toContain('1. Remove evil-pack@1.0.0. It is flagged malicious. Reinstall and rotate credentials.');
    expect(md).toContain('- **Snippet:** `evil-pack@1.0.0`');
    expect(md).toContain('- **Docs:** rules/DEPS-MALICIOUS-001.md');
    expect(md).toContain('- **Fix:** Rotate this credential and store it outside the repo.');
    expect(md.match(/### SAST-SQLI-001/g)).toHaveLength(1);
    expect(md).toContain('src/a.js:2');
    expect(md).toContain('src/b.js:9');
    expect(md).toContain('https://cwe.mitre.org/data/definitions/89.html');
  });

  it('skips a missing first-action kind and keeps a short fix that is already an action', () => {
    const other = finding({
      id: 'other',
      ruleId: 'SAST-CMD-001',
      severity: 'medium',
      remediation: 'Avoid the shell. See https://example.com/docs',
    });
    const text = renderConsoleReport(result([other]));
    expect(text).not.toContain('Remove ');
    expect(text).not.toContain('Upgrade lodash');
    expect(text).not.toContain('Rotate the secret');
    expect(text).toContain('Avoid the shell');
    expect(text).toContain('pass');
  });

  it('names a symbol-reachable bump and an ai finding that does not fail the gate', () => {
    const symbol = finding({
      id: 'sym',
      ruleId: 'DEPS-VULN-001',
      module: 'deps',
      severity: 'critical',
      reachability: 'symbol-reachable',
      snippet: 'lodash@4.17.11',
      title: 'vulnerable dependency',
    });
    const ai = finding({
      id: 'ai',
      ruleId: 'SAST-SQLI-001',
      severity: 'critical',
      source: 'ai',
    });
    const via = finding({
      id: 'via',
      ruleId: 'DEPS-VULN-001',
      module: 'deps',
      severity: 'high',
      reachability: 'reachable-via-dependency',
      snippet: 'qs@6.5.0',
      title: 'vulnerable dependency',
    });
    const low = finding({
      id: 'low',
      ruleId: 'DEPS-VULN-001',
      module: 'deps',
      severity: 'low',
      reachability: 'reachable',
      snippet: 'lodash@4.17.11',
      title: 'vulnerable dependency',
    });
    const text = renderConsoleReport(result([symbol, ai, via, low]));
    expect(text).toContain('Upgrade lodash 4.17.11 → 4.17.21.');
    expect(text).toContain('fail (failOn high, 2 at or above)');
  });

  it('uses the package title, a file without a line, and a singular unused sentence', () => {
    const named = finding({
      id: 'named',
      ruleId: 'DEPS-MALICIOUS-001',
      module: 'deps',
      severity: 'critical',
      title: 'bad-pack',
      snippet: undefined,
      remediation: 'Remove it.',
    });
    const fileSecret = finding({
      id: 'file-secret',
      ruleId: 'SECRET-GENERIC-001',
      module: 'secrets',
      severity: 'low',
      confidence: 'high',
      file: 'src/env.js',
      line: undefined,
      remediation: 'Move it.',
    });
    const rotated = finding({
      id: 'rotated',
      ruleId: 'SAST-LOG-001',
      module: 'sast',
      severity: 'high',
      remediation: 'Rotate this credential before the next deploy.',
    });
    const built = result([named, fileSecret, rotated]);
    built.metadata.upgradePlan = {
      bumps: [
        { name: 'missing', from: '1.0.0', to: '1.0.1', safe: true, findings: 0 },
        { name: 'left-pad', from: '1.0.0', to: '1.1.0', safe: false, findings: 1 },
      ],
      unresolved: [],
      sentence: '',
    };
    built.metadata.unusedDirect = { packages: ['only'], advisories: 1 };
    const text = renderConsoleReport(built);
    expect(text).toContain('Remove bad-pack. It is flagged malicious.');
    expect(text).toContain('Rotate the secret at src/env.js.');
    expect(text).not.toContain('src/env.js:');
    expect(text).toContain('Rotate it, then load it from the environment.');
    expect(text).toContain('1 package is never imported; removing them clears 1 advisory.');
    expect(text).not.toContain('Upgrade missing');
  });
});
