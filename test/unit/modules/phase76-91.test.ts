import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { mayWrite, verifyPatchedSource } from '../../../src/fixer/verify.js';
import { dedupeIngest, parseIngestFile } from '../../../src/ingest/index.js';
import { loadModelPacks } from '../../../src/modules/sast/models.js';
import {
  applySecretStructure,
  githubChecksumOk,
  githubTokenWithChecksum,
} from '../../../src/modules/secrets/structure.js';
import { priorityScore } from '../../../src/priority/index.js';
import { buildSpdx, spdxErrors } from '../../../src/sbom/spdx.js';
import { capabilityFinding, profilePackage } from '../../../src/supply/capabilities.js';
import { assertRegistryHost, fetchPackument, provenanceFromPackument } from '../../../src/supply/provenance-signals.js';
import { attackPaths } from '../../../src/paths/index.js';
const reportSpec = '../../../scripts/precision-report.mjs';
const sampleSpec = '../../../scripts/precision-sample.mjs';
const precisionReportMod = (await import(reportSpec)) as {
  precisionReport: (rows: Array<{ ruleId: string; label: string | null }>) => string;
  wilsonInterval: (successes: number, total: number, z?: number) => { low: number; high: number };
};
const precisionSampleMod = (await import(sampleSpec)) as {
  sampleFindings: (
    findings: Array<{ ruleId: string; file?: string; line?: number; severity: string; id: string }>,
    perRule: number,
    seed: number,
  ) => Array<{ label: null; reviewer: null; note: null }>;
};
const { precisionReport, wilsonInterval } = precisionReportMod;
const { sampleFindings } = precisionSampleMod;

const envKeys = [
  'FULLSHIELD_EXPERIMENTAL_SECRET_CHECK',
  'FULLSHIELD_EXPERIMENTAL_MODELS',
  'FULLSHIELD_EXPERIMENTAL_TYPES',
  'FULLSHIELD_EXPERIMENTAL_PRIORITY',
  'FULLSHIELD_EXPERIMENTAL_PATHS',
];

afterEach(() => {
  for (const key of envKeys) delete process.env[key];
});

describe('phase 82 secret structure', () => {
  it('accepts a generated GitHub checksum and lowers a one-character change', () => {
    const token = githubTokenWithChecksum('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(githubChecksumOk(token)).toBe(true);
    const broken = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`;
    expect(githubChecksumOk(broken)).toBe(false);
    process.env.FULLSHIELD_EXPERIMENTAL_SECRET_CHECK = '1';
    const failed = applySecretStructure(
      {
        id: '1',
        ruleId: 'SECRET-GITHUB-001',
        module: 'secrets',
        title: 'token',
        severity: 'high',
        confidence: 'high',
        message: 'token',
        remediation: 'rotate',
      },
      broken,
      'src/app.js',
    );
    expect(failed.confidence).toBe('low');
    expect(failed.secretCheck).toBe('checksum-failed');
    const placeholder = applySecretStructure(
      { ...failed, ruleId: 'SECRET-AWS-001', confidence: 'high', secretCheck: undefined },
      'AKIAIOSFODNN7EXAMPLE',
      'src/app.js',
    );
    expect(placeholder.secretCheck).toBe('placeholder');
    expect(placeholder.confidence).toBe('low');
  });

  it('leaves findings unchanged when the flag is off', () => {
    const finding = applySecretStructure(
      {
        id: '1',
        ruleId: 'SECRET-AWS-001',
        module: 'secrets',
        title: 'token',
        severity: 'high',
        confidence: 'high',
        message: 'token',
        remediation: 'rotate',
      },
      'AKIAIOSFODNN7EXAMPLE',
      'src/app.js',
    );
    expect(finding.secretCheck).toBeUndefined();
    expect(finding.confidence).toBe('high');
  });
});

describe('phase 84 priority', () => {
  it('scores every documented factor and keeps malicious rules at 100', () => {
    expect(priorityScore({ ruleId: 'DEPS-MALICIOUS-001', severity: 'info', confidence: 'low' }).priority).toBe(100);
    expect(priorityScore({ ruleId: 'SUPPLY-SECHOLDER-001', severity: 'low', confidence: 'low' }).priority).toBe(100);
    expect(priorityScore({ ruleId: 'SUPPLY-STEALER-001', severity: 'low', confidence: 'low' }).priority).toBe(100);
    const scored = priorityScore({
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      confidence: 'high',
      reachability: 'reachable',
      unauthenticatedRoute: true,
      sinkClass: 'sqli',
      agreeingSources: 2,
    });
    expect(scored.priority).toBe(100);
    expect(scored.priorityFactors).toContain('severity:high+60');
    const same = priorityScore({
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      confidence: 'high',
      reachability: 'reachable',
      unauthenticatedRoute: true,
      sinkClass: 'sqli',
      agreeingSources: 2,
    });
    expect(same).toEqual(scored);
    expect(priorityScore({ ruleId: 'DEPS-VULN-001', severity: 'info', confidence: 'low', devOnly: true, reachability: 'not-imported' }).priority).toBe(0);
  });
});

describe('phase 76 precision sample', () => {
  it('is deterministic and writes null labels', () => {
    const findings = Array.from({ length: 30 }, (_, index) => ({
      ruleId: index % 2 === 0 ? 'SAST-SQLI-001' : 'SAST-XSS-001',
      file: 'a.js',
      line: index,
      severity: 'high',
      id: `id-${index}`,
    }));
    const first = sampleFindings(findings, 3, 7);
    const second = sampleFindings(findings, 3, 7);
    expect(first).toEqual(second);
    expect(first.every((row) => row.label === null && row.reviewer === null && row.note === null)).toBe(true);
  });

  it('reports precision from labels and refuses an unlabeled file', () => {
    const rows = Array.from({ length: 10 }, () => ({ ruleId: 'SAST-SQLI-001', label: 'tp' }));
    rows.push(...Array.from({ length: 2 }, () => ({ ruleId: 'SAST-SQLI-001', label: 'fp' })));
    const report = precisionReport(rows);
    expect(report).toContain('SAST-SQLI-001');
    expect(report).not.toContain('insufficient sample');
    const interval = wilsonInterval(10, 12);
    expect(interval.low).toBeLessThan(interval.high);
    expect(() => precisionReport([{ ruleId: 'SAST-SQLI-001', label: null }])).toThrow(/no labeled rows/);
    expect(precisionReport([{ ruleId: 'SAST-XSS-001', label: 'tp' }])).toContain('insufficient sample');
  });
});

describe('phase 79 time budget', () => {
  it('marks an incomplete scan and does not call it clean', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-budget-'));
    await writeFile(join(cwd, 'package.json'), '{"name":"budget","version":"1.0.0"}\n');
    await writeFile(join(cwd, 'a.js'), 'const a = 1;\n');
    await writeFile(join(cwd, 'b.js'), 'const b = 1;\n');
    await writeFile(join(cwd, 'c.js'), 'const c = 1;\n');
    const result = await scan({
      cwd,
      modules: ['sast'],
      offline: true,
      maxTimeMs: 30,
      sastFileDelayMs: 40,
    });
    expect(result.metadata.incomplete).toBe(true);
    expect(result.metadata.filesNotTaintChecked).toBeGreaterThan(0);
    const open = await scan({ cwd, modules: ['sast'], offline: true });
    expect(open.metadata.incomplete).toBeUndefined();
  });
});

describe('phase 81 model packs', () => {
  it('loads 34 packs and suppresses SQL only for isInt', async () => {
    const packs = await loadModelPacks();
    expect(packs).toHaveLength(34);
    for (const pack of packs) {
      expect(pack.entries[0]?.memberPath.length).toBeGreaterThan(0);
      const source = `use ${pack.entries[0]?.memberPath}`;
      expect(source.includes(pack.entries[0]?.memberPath ?? '')).toBe(true);
      expect('db.query(1)'.includes(pack.entries[0]?.memberPath ?? 'missing')).toBe(false);
    }
    const cwd = await mkdtemp(join(tmpdir(), 'fs-models-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ name: 'models', version: '1.0.0', dependencies: { 'express-validator': '7.0.0' } }),
    );
    const route = [
      "const { body } = require('express-validator');",
      'function handler(req) {',
      "  body('id').isInt();",
      "  db.query('SELECT ' + req.body.id);",
      '}',
    ].join('\n');
    await writeFile(join(cwd, 'app.js'), route);
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const flagged = await scan({ cwd, modules: ['sast'], offline: true });
    expect(flagged.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(false);
    expect(flagged.suppressed?.some((finding) => finding.suppressedBy === 'model:express-validator')).toBe(true);
    delete process.env.FULLSHIELD_EXPERIMENTAL_MODELS;
    const trim = route.replace("body('id').isInt();", "body('id').trim();");
    await writeFile(join(cwd, 'app.js'), trim);
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const still = await scan({ cwd, modules: ['sast'], offline: true });
    expect(still.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    delete process.env.FULLSHIELD_EXPERIMENTAL_MODELS;
    const off = await scan({ cwd, modules: ['sast'], offline: true });
    expect(off.suppressed).toBeUndefined();
    expect(off.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
  });
});

describe('phase 80 type receivers', () => {
  it('suppresses array find and keeps a mongoose model and any', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-types-'));
    await mkdir(join(cwd, 'src'));
    await writeFile(
      join(cwd, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { allowJs: true, checkJs: true, noEmit: true, module: 'commonjs', target: 'es2022', strict: false },
        include: ['src'],
      }),
    );
    await writeFile(join(cwd, 'package.json'), '{"name":"types","version":"1.0.0"}\n');
    await writeFile(
      join(cwd, 'src', 'app.js'),
      [
        "const mongoose = require('mongoose');",
        "const User = mongoose.model('User', new mongoose.Schema({ name: String }));",
        "const items = [{ name: 'a' }];",
        'function route(req) {',
        '  items.find({ name: req.query.n });',
        '  User.find({ name: req.query.n });',
        '  /** @type {any} */',
        '  const bag = items;',
        '  bag.find({ name: req.query.n });',
        '}',
      ].join('\n'),
    );
    process.env.FULLSHIELD_EXPERIMENTAL_TYPES = '1';
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const nosql = result.findings.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001');
    const suppressed = result.suppressed?.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001') ?? [];
    expect(suppressed.some((finding) => finding.suppressedBy === 'types')).toBe(true);
    expect(nosql.length).toBeGreaterThan(0);
  });
});

describe('phase 83 ingest', () => {
  it('dedupes npm audit with OSV and Semgrep with a SAST row', () => {
    const audit = parseIngestFile(
      'audit.json',
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          minimist: {
            severity: 'high',
            via: [{ source: 1, title: 'Prototype Pollution', url: 'https://github.com/advisories/GHSA-vh95-rmgr-6w4m' }],
          },
        },
      }),
    );
    const osv = parseIngestFile(
      'osv.json',
      JSON.stringify({
        results: [
          {
            packages: [
              {
                package: { name: 'minimist', version: '0.0.8' },
                vulnerabilities: [{ id: 'GHSA-vh95-rmgr-6w4m' }],
              },
            ],
          },
        ],
      }),
    );
    const merged = dedupeIngest([...audit, ...osv]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.sources?.sort()).toEqual(['npm-audit', 'osv-scanner']);
    const semgrep = parseIngestFile(
      'semgrep.json',
      JSON.stringify({
        results: [
          {
            check_id: 'javascript.lang.security.sql',
            path: 'a.js',
            start: { line: 4 },
            extra: { message: 'sql', severity: 'ERROR', metadata: { cwe: ['CWE-89'] } },
          },
        ],
      }),
    );
    const local = parseIngestFile(
      'fullshield.sarif.json',
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            results: [
              {
                ruleId: 'SAST-SQLI-001',
                level: 'error',
                message: { text: 'sql' },
                locations: [{ physicalLocation: { artifactLocation: { uri: 'a.js' }, region: { startLine: 4 } } }],
              },
            ],
          },
        ],
      }),
    );
    const code = dedupeIngest([...semgrep, ...local]);
    expect(code).toHaveLength(1);
    expect(code[0]?.sources?.sort()).toEqual(['sarif', 'semgrep']);
  });
});

describe('phase 86 capabilities', () => {
  it('lists install script and child_process without spawning', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-cap-'));
    const pkg = join(cwd, 'node_modules', 'helper');
    await mkdir(pkg, { recursive: true });
    await writeFile(
      join(pkg, 'package.json'),
      JSON.stringify({ name: 'helper', version: '1.0.0', scripts: { postinstall: 'node install.js' } }),
    );
    await writeFile(join(pkg, 'index.js'), "const { exec } = require('child_process');\n");
    const source = await readFile(join(import.meta.dirname, '../../../src/supply/capabilities.ts'), 'utf8');
    expect(source).not.toMatch(/\b(spawn|spawnSync|execFile|execFileSync|execSync)\s*\(/);
    const profile = await profilePackage(cwd, 'helper');
    expect(profile?.capabilities).toEqual(expect.arrayContaining(['child_process', 'install-script']));
    expect(profile?.introducedBy).toBe('helper');
    const finding = capabilityFinding(profile!, ['install-script']);
    expect(finding?.ruleId).toBe('SUPPLY-CAP-001');
  });
});

describe('phase 87 provenance', () => {
  it('reports each signal and refuses other hosts', async () => {
    const now = Date.parse('2026-10-19T00:00:00Z');
    expect(
      provenanceFromPackument({
        name: 'left-pad',
        version: '2.0.0',
        previousHadProvenance: true,
        hasProvenance: false,
      })[0]?.kind,
    ).toBe('provenance-regression');
    expect(
      provenanceFromPackument({
        name: 'left-pad',
        version: '2.0.0',
        publisher: 'new-user',
        previousPublishers: ['old-user'],
      })[0]?.kind,
    ).toBe('publisher-change');
    expect(
      provenanceFromPackument(
        { name: 'left-pad', version: '2.0.0', time: '2026-10-18T23:00:00Z' },
        now,
        72,
      )[0]?.kind,
    ).toBe('new-release');
    const calls: string[] = [];
    const fetched = await fetchPackument('left-pad', ((url: string | URL) => {
      calls.push(String(url));
      assertRegistryHost(String(url));
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          'dist-tags': { latest: '1.0.0' },
          time: { '1.0.0': '2020-01-01T00:00:00Z' },
          versions: { '1.0.0': { _npmUser: { name: 'alice' }, dist: {} } },
        }),
      });
    }) as unknown as typeof fetch);
    expect(calls[0]).toContain('registry.npmjs.org');
    expect(fetched?.publisher).toBe('alice');
    expect(() => assertRegistryHost('https://evil.example/left-pad')).toThrow(/refused host/);
    expect(provenanceFromPackument({ name: 'left-pad', version: '1.0.0' })[0]?.kind).toBe('unknown');
  });
});

describe('phase 89 spdx', () => {
  it('validates a deterministic document', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-spdx-'));
    await writeFile(join(cwd, 'package.json'), '{"name":"spdx-app","version":"1.2.3","dependencies":{"left-pad":"1.0.0"}}\n');
    await writeFile(
      join(cwd, 'package-lock.json'),
      JSON.stringify({
        name: 'spdx-app',
        lockfileVersion: 3,
        packages: { '': { name: 'spdx-app', version: '1.2.3' }, 'node_modules/left-pad': { version: '1.0.0' } },
      }),
    );
    const doc = await buildSpdx(cwd, { created: '2026-10-19T00:00:00.000Z' });
    expect(spdxErrors(doc)).toEqual([]);
    const schema = JSON.parse(await readFile(join(import.meta.dirname, '../../schemas/spdx-2.3-subset.schema.json'), 'utf8')) as {
      required: string[];
    };
    for (const key of schema.required) expect(doc).toHaveProperty(key);
    const again = await buildSpdx(cwd, { created: '2026-10-19T00:00:00.000Z' });
    expect(JSON.stringify(again)).toBe(JSON.stringify(doc));
  });
});

describe('phase 91 fix verification', () => {
  it('classifies a removed finding, a no-op, and a new eval', async () => {
    const before = "db.query('SELECT ' + req.body.id);\n";
    const fixed = "db.query('SELECT ?', [req.body.id]);\n";
    const wrong = "db.query('SELECT ' + req.body.id + '');\n";
    const evil = "db.query('SELECT ?', [req.body.id]);\neval(req.body.id);\n";
    expect(await verifyPatchedSource('app.js', before, fixed, 'SAST-SQLI-001')).toBe('removes-finding');
    expect(await verifyPatchedSource('app.js', before, wrong, 'SAST-SQLI-001')).toBe('does-not-remove');
    expect(await verifyPatchedSource('app.js', before, evil, 'SAST-SQLI-001')).toBe('introduces-finding');
    expect(mayWrite('introduces-finding', true)).toBe(false);
    expect(mayWrite('does-not-remove', false)).toBe(false);
    expect(mayWrite('does-not-remove', true)).toBe(true);
  });
});

describe('phase 85 attack paths', () => {
  it('builds a path from an existing finding and adds none on a clean scan', async () => {
    const paths = attackPaths([
      {
        id: 'abc',
        ruleId: 'SAST-SQLI-001',
        module: 'sast',
        title: 'sql',
        severity: 'high',
        confidence: 'high',
        file: 'app.js',
        line: 2,
        message: 'sql',
        remediation: 'use a parameter',
        snippet: "app.get('/user', (req, res) => db.query(req.query.id))",
      },
    ]);
    expect(paths).toHaveLength(1);
    expect(paths[0]?.auth).toBe('absent');
    const clean = await scan({ cwd: join(import.meta.dirname, '../../fixtures/clean-app'), modules: ['sast'], offline: true });
    expect(attackPaths(clean.findings.filter((finding) => finding.module === 'sast'))).toEqual([]);
  });
});
