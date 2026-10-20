import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { scan } from '../../../src/core/engine.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import { summarize, type Finding } from '../../../src/core/finding.js';
import { buildAttackPaths, PATHS_FLAG } from '../../../src/paths/index.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';
import { renderJsonReport } from '../../../src/reporters/json.js';

const fixtures = join(import.meta.dirname, '../../fixtures');
const vulnerable = join(fixtures, 'vulnerable-app');
const clean = join(fixtures, 'clean-app');

afterEach(() => {
  delete process.env[PATHS_FLAG];
});

function keys(findings: readonly Finding[]): string[] {
  return findings.map((f) => `${f.ruleId}\t${f.file ?? ''}\t${f.line ?? ''}\t${f.severity}`);
}

function finding(partial: Pick<Finding, 'id' | 'ruleId' | 'severity' | 'file' | 'line'> & Partial<Finding>): Finding {
  return {
    module: partial.ruleId.startsWith('DEPS') ? 'deps' : partial.ruleId.startsWith('SECRET') ? 'secrets' : 'sast',
    title: partial.ruleId,
    confidence: 'high',
    message: partial.ruleId,
    remediation: 'fix',
    ...partial,
  };
}

async function runCli(args: string[]): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  return { out: out.join('\n'), err: err.join('\n') };
}

describe('phase 85 attack paths', () => {
  it('builds one unauthenticated SQL path on vulnerable-app and does not change findings', async () => {
    const off = await scan({ cwd: vulnerable, modules: ['sast'], offline: true });
    process.env[PATHS_FLAG] = '1';
    const on = await scan({ cwd: vulnerable, modules: ['sast'], offline: true, paths: true });
    expect(keys(on.findings)).toEqual(keys(off.findings));
    expect(on.findings.map((f) => f.severity)).toEqual(off.findings.map((f) => f.severity));
    expect(on.summary).toEqual(off.summary);
    const sql = (on.paths ?? []).filter((path) => path.sink.ruleId === 'SAST-SQLI-001');
    expect(sql).toHaveLength(1);
    expect(sql[0]?.entry).toEqual({ method: 'GET', path: '/user', auth: 'absent' });
    expect(sql[0]?.kind).toBe('sink');
    const sink = on.findings.find((f) => f.id === sql[0]?.sink.id);
    expect(sink?.ruleId).toBe('SAST-SQLI-001');
    expect(sql[0]?.steps).toEqual(sink?.trace ?? []);
    expect(sql[0]?.findingIds).toEqual([sink?.id]);
    expect(new Set(on.findings.map((f) => f.ruleId)).size).toBe(new Set(off.findings.map((f) => f.ruleId)).size);
    const html = renderHtmlReport(on);
    expect(html).toContain('href="#paths"');
    expect(html).toContain('Paths');
    expect(html).toContain('GET /user');
    expect(html).toContain('auth: absent');
    const parsed = JSON.parse(renderJsonReport(on)) as { paths?: unknown };
    expect(Array.isArray(parsed.paths)).toBe(true);
  }, 30_000);

  it('marks router-level auth present and a route registered before auth absent', async () => {
    process.env[PATHS_FLAG] = '1';
    const result = await scan({
      cwd: join(fixtures, 'paths-auth-app'),
      modules: ['sast'],
      offline: true,
      paths: true,
    });
    const sql = (result.paths ?? []).filter((path) => path.sink.ruleId === 'SAST-SQLI-001');
    expect(sql.map((path) => path.entry)).toEqual([
      { method: 'GET', path: '/early', auth: 'present' },
      { method: 'GET', path: '/open', auth: 'absent' },
    ]);
    expect(result.findings.every((f) => f.ruleId !== 'PATHS-001')).toBe(true);
  });

  it('marks a route auth present when auth is mounted on the imported router', async () => {
    process.env[PATHS_FLAG] = '1';
    const result = await scan({
      cwd: join(fixtures, 'paths-inherit-app'),
      modules: ['sast'],
      offline: true,
      paths: true,
    });
    const sql = (result.paths ?? []).filter((path) => path.kind === 'sink');
    expect(sql).toHaveLength(1);
    expect(sql[0]?.entry).toEqual({ method: 'GET', path: '/items', auth: 'present' });
  });

  it('adds no path on clean-app', async () => {
    process.env[PATHS_FLAG] = '1';
    const result = await scan({
      cwd: clean,
      modules: ['sast', 'secrets', 'config'],
      offline: true,
      paths: true,
    });
    expect(result.findings).toEqual([]);
    expect(result.paths).toEqual([]);
    expect(renderConsoleReport(result)).not.toContain('Attack paths');
  });

  it('omits paths when the flag is off', async () => {
    const result = await scan({ cwd: vulnerable, modules: ['sast'], offline: true, paths: true });
    expect(result.paths).toBeUndefined();
    const parsed = JSON.parse(renderJsonReport(result)) as { paths?: unknown };
    expect(parsed.paths).toBeUndefined();
    expect(renderHtmlReport(result)).not.toContain('href="#paths"');
  }, 30_000);

  it('links a used secret identifier and skips an unused one', async () => {
    process.env[PATHS_FLAG] = '1';
    const result = await scan({
      cwd: join(fixtures, 'paths-secret-app'),
      modules: ['secrets', 'sast'],
      offline: true,
      paths: true,
    });
    const jwt = result.findings.find((f) => f.ruleId === 'SECRET-JWT-001');
    const stripe = result.findings.find((f) => f.ruleId === 'SECRET-STRIPE-001');
    expect(jwt).toBeDefined();
    expect(stripe).toBeDefined();
    const linked = (result.paths ?? []).filter((path) => path.kind === 'secret' && path.findingIds.includes(jwt?.id ?? ''));
    expect(linked.length).toBeGreaterThan(0);
    expect(linked[0]?.entry).toEqual({ method: 'GET', path: '/token', auth: 'absent' });
    expect(linked[0]?.steps.some((step) => step.note.includes('JWT_SECRET'))).toBe(true);
    expect((result.paths ?? []).some((path) => path.findingIds.includes(stripe?.id ?? ''))).toBe(false);
    expect(result.findings.map((f) => f.severity)).not.toContain('critical');
  });

  it('sorts by severity when priority is absent, and by priority when it is present', async () => {
    const source = [
      'const db = { query(sql) { return sql; } };',
      'const app = {};',
      "app.get('/low', (req, res) => {",
      "  res.send('<h1>' + req.query.name + '</h1>');",
      '});',
      "app.get('/high', (req, res) => {",
      "  db.query('SELECT ' + req.query.id);",
      '});',
      '',
    ].join('\n');
    const sources = new Map([['src/index.js', source]]);
    const low = finding({
      id: 'low',
      ruleId: 'SAST-XSS-001',
      severity: 'medium',
      file: 'src/index.js',
      line: 4,
    });
    const high = finding({
      id: 'high',
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/index.js',
      line: 7,
    });
    const bySeverity = await buildAttackPaths([low, high], sources);
    expect(bySeverity.map((path) => path.sink.id)).toEqual(['high', 'low']);
    Object.assign(low, { priority: 90 });
    Object.assign(high, { priority: 10 });
    const byPriority = await buildAttackPaths([low, high], sources);
    expect(byPriority.map((path) => path.sink.id)).toEqual(['low', 'high']);
  });

  it('builds a dependency path only for a reachable call inside a route', async () => {
    const inside = [
      "const lodash = require('lodash');",
      "app.get('/merge', (req, res) => {",
      '  lodash.merge({}, req.body);',
      '});',
      '',
    ].join('\n');
    const outside = [
      "const lodash = require('lodash');",
      "app.get('/ok', (req, res) => {",
      "  res.end('ok');",
      '});',
      'lodash.merge({}, {});',
      '',
    ].join('\n');
    const dep = finding({
      id: 'dep',
      ruleId: 'DEPS-VULN-001',
      severity: 'critical',
      file: 'package.json',
      line: 1,
      snippet: 'lodash@4.17.20',
      reachability: 'reachable',
      reachabilityEvidence: {
        imports: [{ file: 'src/index.js', line: 1, specifier: 'lodash' }],
        calls: [{ file: 'src/index.js', line: 3, symbol: 'merge' }],
        reason: 'called',
      },
    });
    const hit = await buildAttackPaths([dep], new Map([['src/index.js', inside]]));
    expect(hit).toHaveLength(1);
    expect(hit[0]?.kind).toBe('dependency');
    expect(hit[0]?.entry).toEqual({ method: 'GET', path: '/merge', auth: 'absent' });
    expect(hit[0]?.findingIds).toEqual(['dep']);
    expect(hit[0]?.steps[0]?.note).toContain('merge');
    const outsideDep = finding({
      ...dep,
      reachabilityEvidence: {
        imports: [{ file: 'src/index.js', line: 1, specifier: 'lodash' }],
        calls: [{ file: 'src/index.js', line: 5, symbol: 'merge' }],
        reason: 'called',
      },
    });
    const miss = await buildAttackPaths([outsideDep], new Map([['src/index.js', outside]]));
    expect(miss).toEqual([]);
    const via = finding({
      ...dep,
      id: 'via',
      reachability: 'reachable-via-dependency',
    });
    expect(await buildAttackPaths([via], new Map([['src/index.js', inside]]))).toEqual([]);
    const discovered = finding({
      id: 'disc',
      ruleId: 'DEPS-VULN-001',
      severity: 'high',
      file: 'package.json',
      line: 1,
      snippet: 'lodash@1.0.0',
      reachability: 'symbol-reachable',
    });
    const found = await buildAttackPaths([discovered], new Map([['src/index.js', inside]]));
    expect(found).toHaveLength(1);
    expect(found[0]?.steps[0]?.note).toContain('merge');
  });

  it('links a secret through the module graph', async () => {
    const secret = [
      "const JWT_SECRET = 'super-secret-jwt-signing-key-fixture';",
      'module.exports = { JWT_SECRET };',
      '',
    ].join('\n');
    const index = [
      "const { JWT_SECRET } = require('./secret');",
      "const jwt = require('jsonwebtoken');",
      'const app = {};',
      "app.get('/token', (req, res) => {",
      "  jwt.sign({ sub: 'a' }, JWT_SECRET);",
      '});',
      '',
    ].join('\n');
    const row = finding({
      id: 'jwt',
      ruleId: 'SECRET-JWT-001',
      severity: 'medium',
      file: 'src/secret.js',
      line: 1,
    });
    const paths = await buildAttackPaths(
      [row],
      new Map([
        ['src/secret.js', secret],
        ['src/index.js', index],
      ]),
    );
    expect(paths).toHaveLength(1);
    expect(paths[0]?.entry).toEqual({ method: 'GET', path: '/token', auth: 'absent' });
    expect(paths[0]?.findingIds).toEqual(['jwt']);
    expect(paths[0]?.steps[0]?.file).toBe('src/index.js');
  });

  it('prints the top 5 paths', () => {
    const paths = ['/a', '/b', '/c', '/d', '/e', '/f'].map((path, index) => ({
      kind: 'sink' as const,
      entry: { method: 'GET', path, auth: 'absent' as const },
      steps: [],
      sink: { id: `id-${index}`, ruleId: 'SAST-SQLI-001', severity: 'high' as const, file: 'src/index.js', line: index + 1 },
      findingIds: [`id-${index}`],
    }));
    const result: ScanResult = {
      findings: [],
      paths,
      summary: summarize([]),
      metadata: {
        version: '0.0.0',
        startedAt: '2026-10-19T00:00:00.000Z',
        durationMs: 1,
        cwd: '/tmp/app',
        filesScanned: 1,
        modulesRequested: ['sast'],
        modulesRun: ['sast'],
      },
      config: structuredClone(DEFAULT_CONFIG),
    };
    const text = renderConsoleReport(result);
    expect(text).toContain('GET /a auth=absent');
    expect(text).toContain('GET /e auth=absent');
    expect(text).not.toContain('GET /f auth=absent');
    expect(text).toContain('1 more paths — use --json');
  });

  it('refuses scan --paths without the flag', async () => {
    const prev = process.exitCode;
    const ran = await runCli(['scan', clean, '--paths', '--offline', '--modules', 'sast']);
    expect(ran.err).toContain(PATHS_FLAG);
    expect(ran.out).toBe('');
    process.exitCode = prev;
  });

  it('accepts scan --paths when --experimental-paths is set', async () => {
    const prev = process.exitCode;
    const ran = await runCli([
      'scan',
      join(fixtures, 'paths-auth-app'),
      '--experimental-paths',
      '--paths',
      '--json',
      '--offline',
      '--modules',
      'sast',
    ]);
    const parsed = JSON.parse(ran.out) as { paths?: Array<{ entry?: { path: string; auth: string } }> };
    expect(parsed.paths?.some((path) => path.entry?.path === '/early' && path.entry.auth === 'present')).toBe(true);
    process.exitCode = prev;
  });
});
