import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderJsonReport } from '../../../src/reporters/json.js';
import {
  PRIORITY_FLAG,
  compareByPriority,
  priorityEnabled,
  scoreFinding,
  scorePriority,
  type PriorityInput,
} from '../../../src/priority/score.js';

const vulnerableApp = join(import.meta.dirname, '../../fixtures/vulnerable-app');
const docPath = join(import.meta.dirname, '../../../docs/priority.md');
const scorePath = join(import.meta.dirname, '../../../src/priority/score.ts');

const base: PriorityInput = {
  ruleId: 'CONFIG-HELMET-001',
  module: 'config',
  severity: 'medium',
  confidence: 'medium',
  routeExposure: 'unknown',
  devOnly: false,
  sinkClass: 'none',
  agreeingSources: 1,
};

function factor(input: PriorityInput, name: string): { points: number; detail: string } | undefined {
  const row = scorePriority(input).factors.find((item) => item.name === name);
  if (row === undefined) return undefined;
  return { points: row.points, detail: row.detail };
}

describe('phase 84 deterministic priority', () => {
  afterEach(() => {
    delete process.env[PRIORITY_FLAG];
  });

  it('documents every factor and omits KEV/EPSS', () => {
    const doc = readFileSync(docPath, 'utf8');
    expect(doc).toContain('FULLSHIELD_EXPERIMENTAL_PRIORITY');
    expect(doc).toContain('Phase 56');
    expect(doc).toMatch(/omitted/i);
    for (const row of [
      'critical | 70',
      'high | 55',
      'medium | 40',
      'low | 20',
      'info | 5',
      'high | 10',
      'low | -10',
      'reachable | 10',
      'symbol-reachable | 10',
      'reachable-via-dependency | 5',
      'imported-not-called | -5',
      'symbol-not-called | -5',
      'not-imported | -15',
      'unauthenticated | 10',
      'dev-only | -20',
      'rce | 10',
      'injection | 8',
      'exposure | 5',
      'proto | 4',
      'credential | 2',
      '2 | 5',
      '3 | 10',
      '4 or more | 15',
    ]) {
      expect(doc).toContain(row);
    }
    const source = readFileSync(scorePath, 'utf8');
    expect(source).not.toMatch(/first\.org|cisa\.gov|nist\.gov|epss/i);
    expect(source).not.toMatch(/\bfetch\b|\bhttp\b|net\.connect/);
  });

  it('scores each factor from the table', () => {
    const cases: Array<{ name: string; patch: Partial<PriorityInput>; score: number; factor: string; points: number }> = [
      { name: 'severity info', patch: { severity: 'info' }, score: 5, factor: 'severity', points: 5 },
      { name: 'severity low', patch: { severity: 'low' }, score: 20, factor: 'severity', points: 20 },
      { name: 'severity medium', patch: { severity: 'medium' }, score: 40, factor: 'severity', points: 40 },
      { name: 'severity high', patch: { severity: 'high' }, score: 55, factor: 'severity', points: 55 },
      { name: 'severity critical', patch: { severity: 'critical' }, score: 70, factor: 'severity', points: 70 },
      { name: 'confidence high', patch: { confidence: 'high' }, score: 50, factor: 'confidence', points: 10 },
      { name: 'confidence medium', patch: { confidence: 'medium' }, score: 40, factor: 'confidence', points: 0 },
      { name: 'confidence low', patch: { confidence: 'low' }, score: 30, factor: 'confidence', points: -10 },
      { name: 'reachable', patch: { reachability: 'reachable' }, score: 50, factor: 'reachability', points: 10 },
      { name: 'symbol-reachable', patch: { reachability: 'symbol-reachable' }, score: 50, factor: 'reachability', points: 10 },
      { name: 'via dependency', patch: { reachability: 'reachable-via-dependency' }, score: 45, factor: 'reachability', points: 5 },
      { name: 'unknown reach', patch: { reachability: 'reachability-unknown' }, score: 40, factor: 'reachability', points: 0 },
      { name: 'absent reach', patch: { reachability: undefined }, score: 40, factor: 'reachability', points: 0 },
      { name: 'imported not called', patch: { reachability: 'imported-not-called' }, score: 35, factor: 'reachability', points: -5 },
      { name: 'symbol not called', patch: { reachability: 'symbol-not-called' }, score: 35, factor: 'reachability', points: -5 },
      { name: 'not imported', patch: { reachability: 'not-imported' }, score: 25, factor: 'reachability', points: -15 },
      { name: 'unauthenticated', patch: { routeExposure: 'unauthenticated' }, score: 50, factor: 'route', points: 10 },
      { name: 'authenticated', patch: { routeExposure: 'authenticated' }, score: 40, factor: 'route', points: 0 },
      { name: 'unknown route', patch: { routeExposure: 'unknown' }, score: 40, factor: 'route', points: 0 },
      { name: 'dev-only', patch: { devOnly: true }, score: 20, factor: 'devOnly', points: -20 },
      { name: 'not dev-only', patch: { devOnly: false }, score: 40, factor: 'devOnly', points: 0 },
      { name: 'sink rce', patch: { sinkClass: 'rce' }, score: 50, factor: 'sink', points: 10 },
      { name: 'sink injection', patch: { sinkClass: 'injection' }, score: 48, factor: 'sink', points: 8 },
      { name: 'sink exposure', patch: { sinkClass: 'exposure' }, score: 45, factor: 'sink', points: 5 },
      { name: 'sink proto', patch: { sinkClass: 'proto' }, score: 44, factor: 'sink', points: 4 },
      { name: 'sink credential', patch: { sinkClass: 'credential' }, score: 42, factor: 'sink', points: 2 },
      { name: 'sink none', patch: { sinkClass: 'none' }, score: 40, factor: 'sink', points: 0 },
      { name: 'sink unknown', patch: { sinkClass: 'not-a-class' }, score: 40, factor: 'sink', points: 0 },
      { name: 'sources 0', patch: { agreeingSources: 0 }, score: 40, factor: 'sources', points: 0 },
      { name: 'sources 1', patch: { agreeingSources: 1 }, score: 40, factor: 'sources', points: 0 },
      { name: 'sources 2', patch: { agreeingSources: 2 }, score: 45, factor: 'sources', points: 5 },
      { name: 'sources 3', patch: { agreeingSources: 3 }, score: 50, factor: 'sources', points: 10 },
      { name: 'sources 4', patch: { agreeingSources: 4 }, score: 55, factor: 'sources', points: 15 },
      { name: 'sources 9', patch: { agreeingSources: 9 }, score: 55, factor: 'sources', points: 15 },
    ];
    for (const row of cases) {
      const scored = scorePriority({ ...base, ...row.patch });
      expect(scored.priority, row.name).toBe(row.score);
      expect(factor({ ...base, ...row.patch }, row.factor)?.points, row.name).toBe(row.points);
      expect(scored.factors.map((item) => item.name)).toEqual([
        'severity',
        'confidence',
        'reachability',
        'route',
        'devOnly',
        'sink',
        'sources',
      ]);
    }
  });

  it('derives sink class from the rule id and secret module', () => {
    const sqli = scorePriority({ ...base, ruleId: 'SAST-SQLI-001', sinkClass: undefined });
    expect(factor({ ...base, ruleId: 'SAST-SQLI-001', sinkClass: undefined }, 'sink')).toEqual({
      points: 8,
      detail: 'injection',
    });
    expect(sqli.priority).toBe(48);
    const explicit = scorePriority({ ...base, ruleId: 'SAST-SQLI-001', sinkClass: 'none' });
    expect(explicit.priority).toBe(40);
    const secret = scorePriority({ ...base, ruleId: 'SECRET-AWS-001', module: 'secrets', sinkClass: undefined });
    expect(factor({ ...base, ruleId: 'SECRET-AWS-001', module: 'secrets', sinkClass: undefined }, 'sink')).toEqual({
      points: 2,
      detail: 'credential',
    });
    expect(secret.priority).toBe(42);
    expect(scorePriority({ ...base, ruleId: 'SAST-XSS-001', sinkClass: undefined }).priority).toBe(45);
  });

  it('forces supply and malicious rules to 100', () => {
    const worst: PriorityInput = {
      ruleId: 'DEPS-VULN-001',
      severity: 'info',
      confidence: 'low',
      reachability: 'not-imported',
      routeExposure: 'unknown',
      devOnly: true,
      sinkClass: 'none',
      agreeingSources: 0,
    };
    expect(scorePriority(worst).priority).toBe(0);
    expect(scorePriority(worst).factors.some((item) => item.name === 'always')).toBe(false);
    for (const ruleId of ['DEPS-MALICIOUS-001', 'SUPPLY-SECHOLDER-001', 'SUPPLY-STEALER-001'] as const) {
      const scored = scorePriority({ ...worst, ruleId, severity: 'info' });
      expect(scored.priority).toBe(100);
      expect(scored.factors).toEqual([{ name: 'always', points: 100, detail: ruleId }]);
    }
  });

  it('clamps to 0–100', () => {
    const high = scorePriority({
      ...base,
      severity: 'critical',
      confidence: 'high',
      reachability: 'reachable',
      routeExposure: 'unauthenticated',
      sinkClass: 'rce',
      agreeingSources: 4,
    });
    expect(high.priority).toBe(100);
    expect(high.factors.reduce((sum, item) => sum + item.points, 0)).toBe(125);
    const low = scorePriority({
      ...base,
      severity: 'info',
      confidence: 'low',
      reachability: 'not-imported',
      devOnly: true,
    });
    expect(low.priority).toBe(0);
    expect(low.factors.reduce((sum, item) => sum + item.points, 0)).toBe(-40);
  });

  it('returns the same score for the same input', () => {
    const severities = ['info', 'low', 'medium', 'high', 'critical'] as const;
    const confidences = ['low', 'medium', 'high'] as const;
    const reaches = [
      undefined,
      'reachable',
      'symbol-reachable',
      'reachable-via-dependency',
      'reachability-unknown',
      'imported-not-called',
      'symbol-not-called',
      'not-imported',
    ] as const;
    const routes = [undefined, 'unauthenticated', 'authenticated', 'unknown'] as const;
    const sinks = [undefined, 'rce', 'injection', 'exposure', 'proto', 'credential', 'none', 'other'] as const;
    const counts = [undefined, 0, 1, 2, 3, 4, 8];
    let seen = 0;
    let mismatches = 0;
    for (const severity of severities) {
      for (const confidence of confidences) {
        for (const reachability of reaches) {
          for (const routeExposure of routes) {
            for (const devOnly of [false, true]) {
              for (const sinkClass of sinks) {
                for (const agreeingSources of counts) {
                  const input: PriorityInput = {
                    ruleId: 'SAST-PATH-001',
                    severity,
                    confidence,
                    reachability,
                    routeExposure,
                    devOnly,
                    sinkClass,
                    agreeingSources,
                  };
                  const left = scorePriority(input);
                  const right = scorePriority({ ...input });
                  seen += 1;
                  if (left.priority !== right.priority || JSON.stringify(left.factors) !== JSON.stringify(right.factors)) {
                    mismatches += 1;
                  }
                  if (!Number.isInteger(left.priority) || left.priority < 0 || left.priority > 100) mismatches += 1;
                  const frozen = scorePriority({
                    ...input,
                    ruleId: 'SUPPLY-STEALER-001',
                  });
                  if (frozen.priority !== 100 || frozen.factors.length !== 1) mismatches += 1;
                }
              }
            }
          }
        }
      }
    }
    expect(seen).toBe(5 * 3 * 8 * 4 * 2 * 8 * 7);
    expect(mismatches).toBe(0);
    const calls: string[] = [];
    const prev = globalThis.fetch;
    globalThis.fetch = ((url: string) => {
      calls.push(String(url));
      return Promise.reject(new Error('network'));
    }) as typeof fetch;
    try {
      scorePriority(base);
    } finally {
      globalThis.fetch = prev;
    }
    expect(calls).toEqual([]);
    expect(priorityEnabled()).toBe(false);
  });

  it('does not change severity and leaves JSON unchanged when the flag is off', async () => {
    expect(priorityEnabled()).toBe(false);
    const off = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const json = renderJsonReport(off);
    expect(json).not.toContain('"priority"');
    expect(json).not.toContain('priorityFactors');
    const again = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    expect(JSON.stringify(again.findings)).toBe(JSON.stringify(off.findings));

    process.env[PRIORITY_FLAG] = '1';
    const on = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    expect(on.findings.map((finding) => finding.id)).toEqual(off.findings.map((finding) => finding.id));
    for (const finding of on.findings) {
      const previous = off.findings.find((row) => row.id === finding.id);
      expect(previous).toBeDefined();
      expect(finding.severity).toBe(previous?.severity);
      expect(finding.priority).toEqual(expect.any(Number));
      expect(finding.priorityFactors?.length).toBeGreaterThan(0);
      const rest = { ...finding };
      delete rest.priority;
      delete rest.priorityFactors;
      expect(rest).toEqual(previous);
    }
    const cmdi = on.findings.find((finding) => finding.ruleId === 'SAST-CMDI-001');
    const sqli = on.findings.find((finding) => finding.ruleId === 'SAST-SQLI-001' && finding.file === 'src/index.js');
    const auth = on.findings.find((finding) => finding.ruleId === 'SAST-AUTH-001');
    expect(cmdi?.priorityFactors?.find((item) => item.name === 'sink')).toMatchObject({ points: 10, detail: 'rce' });
    expect(sqli?.priorityFactors?.find((item) => item.name === 'sink')).toMatchObject({ points: 8, detail: 'injection' });
    expect(auth?.priorityFactors?.find((item) => item.name === 'route')).toMatchObject({
      points: 10,
      detail: 'unauthenticated',
    });
    expect(cmdi?.priority).toBeGreaterThan(sqli?.priority ?? 100);
    const sample: Finding = {
      id: 'x',
      ruleId: 'SAST-SQLI-001',
      module: 'sast',
      title: 'sql',
      severity: 'high',
      confidence: 'high',
      message: 'query',
      remediation: 'fix',
    };
    expect(scoreFinding(sample).priority).toBe(73);
    expect(sample.severity).toBe('high');
    expect(sample.priority).toBeUndefined();
  });

  it('sorts the vulnerable-app console by priority, then severity, then file', async () => {
    process.env[PRIORITY_FLAG] = '1';
    const result = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const text = stripAnsi(renderConsoleReport(result, { all: true }));
    const printed = [...text.matchAll(/^\s+\[([A-Z0-9-]+)\][^(]*\(([^)]+)\)/gm)].map(
      (match) => `${match[1]} ${match[2]}`,
    );
    const expected = [...result.findings].sort(compareByPriority).map((finding) => {
      const location =
        finding.file !== undefined
          ? `${finding.file}${finding.line !== undefined ? `:${finding.line}` : ''}`
          : '(project)';
      return `${finding.ruleId} ${location}`;
    });
    expect(printed).toEqual(expected);
  });

  it('keeps severity order in the console when the flag is off', () => {
    const critical: Finding = {
      id: 'c',
      ruleId: 'SAST-CRYPTO-001',
      module: 'sast',
      title: 'crypto',
      severity: 'critical',
      confidence: 'low',
      file: 'z.js',
      line: 1,
      message: 'weak',
      remediation: 'fix',
      priority: 1,
    };
    const high: Finding = {
      id: 'h',
      ruleId: 'SAST-SQLI-001',
      module: 'sast',
      title: 'sql',
      severity: 'high',
      confidence: 'high',
      file: 'a.js',
      line: 2,
      message: 'query',
      remediation: 'fix',
      priority: 99,
    };
    const off = stripAnsi(
      renderConsoleReport(scanResult([critical, high]), { all: true }),
    );
    expect(off.indexOf('z.js:1')).toBeLessThan(off.indexOf('a.js:2'));
    expect(off).not.toContain('"priority"');

    process.env[PRIORITY_FLAG] = '1';
    const on = stripAnsi(renderConsoleReport(scanResult([critical, high]), { all: true }));
    expect(on.indexOf('a.js:2')).toBeLessThan(on.indexOf('z.js:1'));
  });

  it('accepts --experimental-priority', async () => {
    const program = createProgram({ out: () => undefined, err: () => undefined });
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand?.helpInformation()).toContain('--experimental-priority');
    expect(scanCommand?.helpInformation()).toContain(PRIORITY_FLAG);
    const saved = process.exitCode;
    await program.parseAsync(['node', 'fullshield', 'scan', join(vulnerableApp, 'missing-dir'), '--experimental-priority']);
    expect(process.env[PRIORITY_FLAG]).toBe('1');
    process.exitCode = saved;
  });
});

function stripAnsi(text: string): string {
  return text.replace(/\u001b\[[0-9;]*m/g, '');
}

function scanResult(findings: Finding[]) {
  return {
    findings,
    summary: {
      total: findings.length,
      bySeverity: {
        info: 0,
        low: 0,
        medium: 0,
        high: findings.filter((row) => row.severity === 'high').length,
        critical: findings.filter((row) => row.severity === 'critical').length,
      },
    },
    metadata: {
      version: '0.4.0',
      startedAt: '2026-10-19T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['sast'] as const,
      modulesRun: ['sast'] as const,
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}
