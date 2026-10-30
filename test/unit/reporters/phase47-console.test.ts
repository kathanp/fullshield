import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { failsCi, type Finding } from '../../../src/core/finding.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';
import { renderJsonReport } from '../../../src/reporters/json.js';
import { renderMarkdownReport } from '../../../src/reporters/markdown.js';
import { renderSarifReport } from '../../../src/reporters/sarif.js';

function finding(partial: Partial<Finding> & Pick<Finding, 'id' | 'ruleId' | 'severity'>): Finding {
  return {
    module: 'deps',
    title: partial.ruleId,
    confidence: 'high',
    file: 'package-lock.json',
    line: 1,
    message: partial.ruleId,
    remediation: 'fix',
    ...partial,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: {
      total: findings.length,
      bySeverity: {
        info: findings.filter((row) => row.severity === 'info').length,
        low: findings.filter((row) => row.severity === 'low').length,
        medium: findings.filter((row) => row.severity === 'medium').length,
        high: findings.filter((row) => row.severity === 'high').length,
        critical: findings.filter((row) => row.severity === 'critical').length,
      },
    },
    metadata: {
      version: '0.4.0',
      startedAt: new Date().toISOString(),
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['deps', 'sast', 'config'],
      modulesRun: ['deps', 'sast', 'config'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

describe('Phase 47 console (human decision 2026-10-18)', () => {
  const viaA = finding({
    id: 'lodash-a',
    ruleId: 'DEPS-VULN-001',
    severity: 'high',
    reachability: 'reachable-via-dependency',
    snippet: 'lodash@4.17.11',
    dependencyPath: ['express', 'lodash'],
    file: 'package.json',
    line: 8,
    message: 'lodash advisory A. Reachable via express > lodash.',
  });
  const viaB = finding({
    id: 'lodash-b',
    ruleId: 'DEPS-VULN-001',
    severity: 'medium',
    reachability: 'reachable',
    snippet: 'lodash@4.17.15',
    dependencyPath: ['app', 'lodash'],
    file: 'src/app.js',
    line: 3,
    message: 'lodash advisory B',
  });
  const notImported = finding({
    id: 'unused',
    ruleId: 'DEPS-VULN-001',
    severity: 'critical',
    confidence: 'high',
    reachability: 'not-imported',
    snippet: 'leftpad@1.0.0',
    file: 'package-lock.json',
    line: 40,
  });
  const devOnly = finding({
    id: 'dev',
    ruleId: 'DEPS-VULN-001',
    severity: 'info',
    reachability: 'reachable',
    snippet: 'mocha@6.0.0',
    message: 'mocha advisory (dev-only)',
  });
  const typosquat = finding({
    id: 'typo',
    ruleId: 'DEPS-TYPOSQUAT-001',
    severity: 'medium',
    confidence: 'low',
    snippet: 'expresss@1.0.0',
    file: 'package.json',
    line: 9,
  });
  const malicious = finding({
    id: 'mal',
    ruleId: 'DEPS-MALICIOUS-001',
    severity: 'critical',
    reachability: 'not-imported',
    snippet: 'evil-pack@1.2.3',
    file: 'package.json',
    line: 4,
  });
  const highSast = finding({
    id: 'sast-high',
    ruleId: 'SAST-SQLI-001',
    module: 'sast',
    severity: 'high',
    confidence: 'medium',
    file: 'a.js',
    line: 4,
  });
  const lowSast = finding({
    id: 'sast-low',
    ruleId: 'SAST-AUTH-001',
    module: 'sast',
    severity: 'low',
    confidence: 'low',
    file: 'a.js',
    line: 8,
  });

  const mixed = result([viaA, viaB, notImported, devOnly, typosquat, malicious, highSast, lowSast]);

  it('groups reachable advisories for one package and folds the rest', () => {
    const text = renderConsoleReport(mixed);
    expect(text).toContain('lodash');
    expect(text).toContain('2 advisories');
    expect(text).toContain('4.17.11');
    expect(text).toContain('4.17.15');
    expect(text).toContain('reachable');
    expect(text).toContain('express > lodash');
    expect(text).toContain('package.json:8');
    expect(text).toContain('evil-pack');
    expect(text).toContain('a.js:4');
    expect(text).not.toContain('leftpad');
    expect(text).not.toContain('mocha');
    expect(text).not.toContain('expresss');
    expect(text).not.toContain('a.js:8');
    expect(text).toContain('4 more (not directly reachable, or below high confidence) — --all or --markdown report.md');
    expect(text.indexOf('evil-pack')).toBeLessThan(text.indexOf('lodash'));
    expect(text.indexOf('lodash')).toBeLessThan(text.indexOf('a.js:4'));
    expect(text.match(/lodash/g)?.length).toBeGreaterThan(0);
    expect(text.split('\n').filter((line) => line.includes('[DEPS-VULN-001]') && line.includes('lodash'))).toHaveLength(1);
  });

  it('keeps JSON, SARIF, Markdown, and HTML as one entry per finding', () => {
    const json = renderJsonReport(mixed);
    const sarif = renderSarifReport(mixed);
    const markdown = renderMarkdownReport(mixed);
    const html = renderHtmlReport(mixed);
    const parsed = JSON.parse(json) as { findings: Finding[] };
    expect(parsed.findings.map((row) => row.id).sort()).toEqual(
      ['dev', 'lodash-a', 'lodash-b', 'mal', 'sast-high', 'sast-low', 'typo', 'unused'].sort(),
    );
    expect(json).toContain('leftpad@1.0.0');
    expect(sarif.match(/"ruleId":/g)).toHaveLength(8);
    expect(markdown.match(/### DEPS-VULN-001/g)).toHaveLength(4);
    expect(markdown).toContain('package-lock.json:40');
    expect(html.match(/DEPS-VULN-001/g)?.length).toBeGreaterThanOrEqual(4);
  });

  it('still fails the high gate when a folded dependency finding is high', () => {
    const foldedHigh = finding({
      id: 'high-unused',
      ruleId: 'DEPS-VULN-001',
      severity: 'high',
      confidence: 'high',
      reachability: 'not-imported',
      snippet: 'old@1.0.0',
    });
    const text = renderConsoleReport(result([foldedHigh]));
    expect(text).not.toContain('old@1.0.0');
    expect(failsCi(foldedHigh, 'high')).toBe(true);
  });

  it('caps grouped rows at 20', () => {
    const many = Array.from({ length: 21 }, (_, index) =>
      finding({
        id: `pkg-${index}`,
        ruleId: 'DEPS-VULN-001',
        severity: 'high',
        reachability: 'reachable',
        snippet: `pkg${String(index).padStart(2, '0')}@1.0.0`,
        file: 'package.json',
        line: index + 1,
      }),
    );
    const text = renderConsoleReport(result(many));
    expect(text).toContain('pkg00');
    expect(text).not.toContain('pkg20');
    expect(text).toContain('1 more: --all and --markdown report.md');
    const all = renderConsoleReport(result(many), { all: true });
    expect(all).toContain('pkg20');
    expect(all).not.toContain('more actionable');
  });

  it('prints no finding rows when the result is empty', () => {
    const text = renderConsoleReport(result([]));
    expect(text).toContain('No findings');
    expect(text).not.toContain('more (not directly reachable');
  });
});
