import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';

import { afterEach, describe, expect, it } from 'vitest';

import { applyDiffGate } from '../../../src/agent/diff-gate.js';
import { confirmIsPass, confirmLabel } from '../../../src/confirm/index.js';
import { failsCi, type Finding } from '../../../src/core/finding.js';
import { applyReviewedPrecision, reviewedPrecisionRows } from '../../../src/core/reviewed-gate.js';
import { unifiedDiff } from '../../../src/fixer/diff.js';
import { openVerifiedFixPr } from '../../../src/fixer/pull-request.js';
import { verifyFixInCopy } from '../../../src/fixer/temp-verify.js';
import { proveUpgrade } from '../../../src/fixer/upgrade-proof.js';
import { symbolsForReviewedRows } from '../../../src/modules/deps/vuln-functions.js';
import { runSastOnText } from '../../../src/modules/sast/index.js';
import { installFirewallFindings } from '../../../src/supply/install-firewall.js';

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(patch: Partial<Finding> = {}): Finding {
  return {
    id: '1',
    ruleId: 'SAST-EVAL-001',
    module: 'sast',
    title: 'eval',
    severity: 'high',
    confidence: 'high',
    file: 'a.js',
    line: 4,
    message: 'eval',
    remediation: 'remove it',
    ...patch,
  };
}

describe('3.6.1 scanner advances', () => {
  it('blocks a malicious advisory, a typosquat, a changed install script, and a young release', () => {
    const ids = installFirewallFindings({
      name: 'lodasx',
      advisories: ['MAL-2024-0001'],
      scripts: { preinstall: 'node steal.js' },
      previousScripts: {},
      provenance: false,
      publisher: 'new',
      previousPublisher: 'old',
      publishedAt: '2026-11-02T00:00:00.000Z',
      now: '2026-11-03T00:00:00.000Z',
      minAgeDays: 7,
    }).map((row) => row.ruleId);
    expect(ids).toEqual(expect.arrayContaining([
      'SUPPLY-MAL-001',
      'DEPS-TYPOSQUAT-001',
      'SUPPLY-SCRIPT-001',
      'SUPPLY-PROVENANCE-001',
      'SUPPLY-PUBLISHER-001',
      'SUPPLY-AGE-001',
    ]));
    expect(installFirewallFindings({ name: 'left-pad' })).toEqual([]);
  });

  it('does not treat an unconfirmed canary as a pass', () => {
    expect(confirmIsPass([{ status: 'unconfirmed' }])).toBe(false);
    expect(confirmIsPass([{ status: 'confirmed' }])).toBe(true);
    expect(confirmLabel('confirmed')).toBe('confirmed-exploitable');
    expect(failsCi(finding({ gate: false }), 'low')).toBe(false);
  });

  it('ignores an unlabeled precision row and gates a reviewed rule under 80%', () => {
    const rows = reviewedPrecisionRows({
      rows: [
        { ruleId: 'SAST-EVAL-001', precision: 0.4, n: 6, reviewer: 'ada' },
        { ruleId: 'SAST-SQLI-001', precision: 0.2, n: 9 },
      ],
    });
    expect(rows.map((row) => row.ruleId)).toEqual(['SAST-EVAL-001']);
    const [quiet, kept] = applyReviewedPrecision(
      [finding(), finding({ id: '2', ruleId: 'SAST-SQLI-001' })],
      rows,
    );
    expect(quiet?.gate).toBe(false);
    expect(kept?.gate).toBeUndefined();
  });

  it('attaches a reviewed symbol only when the advisory id is on the finding', () => {
    const rows = [{
      osvId: 'GHSA-test-0000',
      package: 'left-pad',
      symbol: 'parse',
      source: 'https://github.com/advisories/GHSA-test-0000',
    }];
    const matched = symbolsForReviewedRows([finding({
      ruleId: 'DEPS-VULN-001',
      module: 'deps',
      references: ['GHSA-test-0000'],
    })], rows);
    expect(matched.get('1')).toEqual(['parse']);
    expect(symbolsForReviewedRows([finding()], rows).size).toBe(0);
  });

  it('keeps a finding on a changed line and drops the gate for the rest', () => {
    const hunks = new Map<string, Array<[number, number]>>([['a.js', [[4, 4]]]]);
    const [hit, miss] = applyDiffGate([finding(), finding({ id: '2', line: 9 })], hunks);
    expect(hit?.gate).toBeUndefined();
    expect(miss?.gate).toBe(false);
  });

  it('runs project tests in the temp copy and leaves the source unchanged', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-verify-'));
    dirs.push(cwd);
    const source = 'function go(req) { eval(req.body.code); }\n';
    await writeFile(join(cwd, 'a.js'), source, 'utf8');
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ scripts: { test: 'node -e "process.exit(1)"' } }), 'utf8');
    const diff = unifiedDiff('a.js', source, 'function go(req) { return req.body.code; }\n');
    const status = await verifyFixInCopy({ cwd, file: 'a.js', diff, ruleId: 'SAST-EVAL-001' });
    expect(status).toBe('fixed-tests-fail');
    expect(await readFile(join(cwd, 'a.js'), 'utf8')).toBe(source);
  });

  it('reports an upgrade from the injected installer and opens a pull request without merging', async () => {
    const broke = await proveUpgrade({
      spec: 'left-pad@1.0.0',
      install: () => Promise.resolve(true),
      test: () => Promise.resolve(false),
    });
    const safe = await proveUpgrade({
      spec: 'left-pad@1.0.0',
      install: () => Promise.resolve(true),
      test: () => Promise.resolve(true),
    });
    expect(broke).toBe('upgrade-breaks-tests');
    expect(safe).toBe('upgrade-safe');
    const args: string[][] = [];
    const opened = await openVerifiedFixPr({
      title: 'fix: SAST-EVAL-001',
      body: 'temp copy',
      run: (command) => {
        args.push([...command]);
        return Promise.resolve({ status: 0, stdout: 'https://example.invalid/pull/1\n' });
      },
    });
    expect(opened.stdout).toContain('https://example.invalid/pull/1');
    expect(args[0]?.join(' ')).toBe('pr create --title fix: SAST-EVAL-001 --body temp copy');
    expect(args[0]).not.toContain('merge');
    expect(args[0]).not.toContain('comment');
  });

  it('reports nest, next, and fastify sinks and ignores the guarded or schema forms', async () => {
    const root = join(process.cwd(), 'test', 'fixtures', 'frameworks');
    const nestVuln = await runSastOnText('items.controller.ts', await readFile(join(root, 'nest-vuln', 'items.controller.ts'), 'utf8'));
    const nestClean = await runSastOnText('items.controller.ts', await readFile(join(root, 'nest-clean', 'items.controller.ts'), 'utf8'));
    const nextVuln = await runSastOnText('app/api/items/route.ts', await readFile(join(root, 'next-vuln', 'app', 'api', 'items', 'route.ts'), 'utf8'));
    const nextClean = await runSastOnText('app/api/items/route.ts', await readFile(join(root, 'next-clean', 'app', 'api', 'items', 'route.ts'), 'utf8'));
    const nextAction = await runSastOnText('app/actions.ts', await readFile(join(root, 'next-vuln', 'app', 'actions.ts'), 'utf8'));
    expect(nestVuln.map((row) => row.ruleId)).toContain('SAST-NEST-001');
    expect(nestClean.map((row) => row.ruleId)).not.toContain('SAST-NEST-001');
    expect(nextVuln.map((row) => row.ruleId)).toContain('SAST-NEXT-ROUTE-001');
    expect(nextClean.map((row) => row.ruleId)).not.toContain('SAST-NEXT-ROUTE-001');
    expect(nextAction.map((row) => row.ruleId)).toContain('SAST-NEXT-001');
    const fastifyVuln = await runSastOnText('app.js', await readFile(join(root, 'fastify-vuln', 'app.js'), 'utf8'));
    const fastifyClean = await runSastOnText('app.js', await readFile(join(root, 'fastify-clean', 'app.js'), 'utf8'));
    expect(fastifyVuln.map((row) => row.ruleId)).toContain('SAST-FASTIFY-001');
    expect(fastifyClean.map((row) => row.ruleId)).not.toContain('SAST-FASTIFY-001');
  });

  it('records a localhost route and does not write a network host', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-record-'));
    dirs.push(cwd);
    const preload = join(process.cwd(), 'src', 'record', 'preload.mjs');
    const runner = join(cwd, 'run.mjs');
    const preloadUrl = pathToFileURL(preload).href;
    const appUrl = pathToFileURL(join(cwd, 'app.mjs')).href;
    await writeFile(runner, `import ${JSON.stringify(preloadUrl)};\nawait import(${JSON.stringify(appUrl)});\n`, 'utf8');
    await writeFile(join(cwd, 'app.mjs'), [
      "import http from 'node:http';",
      "const server = http.createServer((req, res) => { res.end('ok'); });",
      "server.listen(0, '127.0.0.1', () => {",
      '  const address = server.address();',
      "  const port = typeof address === 'object' && address !== null ? address.port : 0;",
      "  http.get('http://127.0.0.1:' + port + '/health', () => { server.close(); });",
      '});',
      '',
    ].join('\n'), 'utf8');
    const code = await new Promise<number>((done) => {
      const child = spawn(process.execPath, [runner], {
        cwd,
        stdio: 'ignore',
      });
      child.once('exit', (status) => done(status ?? 1));
      child.once('error', () => done(1));
    });
    expect(code).toBe(0);
    const saved = await readFile(join(cwd, '.fullshield', 'evidence.json'), 'utf8');
    expect(saved).toContain('GET /health');
    expect(saved).not.toContain('https://');
  });
});
