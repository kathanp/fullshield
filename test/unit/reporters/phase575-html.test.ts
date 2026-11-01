import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { summarize, type Finding, type Severity } from '../../../src/core/finding.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';

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
      version: '3.5.4',
      startedAt: '2026-10-31T00:00:00.000Z',
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
      unusedDirect: { packages: ['left-pad'], advisories: 1 },
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
  built.config.failOn = failOn;
  return built;
}

describe('phase 575 html report', () => {
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
    dependencyPath: ['express', 'lodash'],
  });
  const secret = finding({
    id: 'sec',
    ruleId: 'SECRET-AWS-001',
    module: 'secrets',
    severity: 'high',
    file: 'src/keys.js',
    line: 4,
    title: 'AWS key',
    message: 'key <live>',
    remediation: 'Rotate this credential and store it outside the repo.',
  });
  const sqliA = finding({
    id: 'a',
    ruleId: 'SAST-SQLI-001',
    file: 'src/a.js',
    line: 2,
    severity: 'high',
    snippet: 'db.query(a+b)',
    trace: [{ file: 'src/a.js', line: 2, note: 'taint' }],
    explanation: 'why',
  });
  const sqliB = finding({
    id: 'b',
    ruleId: 'SAST-SQLI-001',
    file: 'src/b.js',
    line: 9,
    severity: 'medium',
    title: 'SQL injection',
    remediation: 'SQL injection. See https://cwe.mitre.org/data/definitions/89.html',
  });

  it('uses the shared opening, three first actions, and one heading per severity', () => {
    const html = renderHtmlReport(result([malicious, bump, secret, sqliA, sqliB]));
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('5 findings: 1 critical, 3 high, 1 medium');
    expect(html).toContain('Fail: failOn is high. fail (failOn high, 4 at or above).');
    expect(html).toContain('<h2>high (3)</h2>');
    expect(html).toContain('<h2>Do this first</h2>');
    expect(html).toContain('Remove evil-pack@1.0.0. It is flagged malicious. Reinstall and rotate credentials.');
    expect(html).toContain('Upgrade lodash 4.17.11 → 4.17.21.');
    expect(html).toContain('Rotate the secret at src/keys.js:4.');
    expect(html).toContain('1 dependency has a fixed version.');
    expect(html).toContain('1 package is never imported; removing them clears 1 advisory.');
    expect(html.match(/<h3>SAST-SQLI-001/g)).toHaveLength(2);
    expect(html).toContain('src/a.js:2');
    expect(html).toContain('src/b.js:9');
    expect(html).toContain('db.query(a+b)');
    expect(html).toContain('express &gt; lodash');
    expect(html).toContain('Reachability: reachable');
    expect(html).toContain('why');
    expect(html).toContain('Docs: rules/SAST-SQLI-001.md');
    expect(html).toContain('https://cwe.mitre.org/data/definitions/89.html');
    expect(html).toContain('Rotate this credential and store it outside the repo.');
    expect(html).toContain('key &lt;live&gt;');
    expect(html).not.toContain('key <live>');
  });

  it('says pass when nothing meets failOn and keeps an empty report', () => {
    const info = finding({
      id: 'info',
      ruleId: 'CONFIG-SCRIPTS-001',
      module: 'config',
      severity: 'info',
      confidence: 'medium',
    });
    const text = renderHtmlReport(result([info], 'high'));
    expect(text).toContain('Pass: failOn is high.');
    expect(text).not.toContain('Fail:');
    expect(renderHtmlReport(result([]))).toContain('No findings.');
    expect(renderHtmlReport(result([]))).toContain('Pass: failOn is high.');
  });

  it('draws the taint edge only when the edges argument is on', () => {
    const both = finding({
      id: 'edge',
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      message: 'concat',
      trace: [
        { file: 'src/in.js', line: 2, note: 'source' },
        { file: 'src/out.js', line: 9, note: 'sink' },
      ],
    });
    const on = renderHtmlReport(result([both]), true);
    expect(on).toContain('<p class="taint">source src/in.js:2 sink src/out.js:9</p>');
    const off = renderHtmlReport(result([both]), false);
    expect(off).not.toContain('taint');
    expect(off).toBe(renderHtmlReport(result([both])));
  });
});
