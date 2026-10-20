import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { scan } from '../../../src/core/engine.js';
import { ingestLocalFiles } from '../../../src/ingest/index.js';
import { validateSarif21 } from '../../../src/reporters/sarif.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/ingest');
const dirs: string[] = [];

function fixture(name: string): string {
  return join(fixtures, name);
}

async function runCli(args: string[]): Promise<{ out: string; err: string; code: number }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  const before = process.exitCode;
  process.exitCode = undefined;
  await program.parseAsync(['node', 'fullshield', ...args]);
  const code = process.exitCode === undefined ? 0 : Number(process.exitCode);
  process.exitCode = before;
  return { out: out.join('\n'), err: err.join('\n'), code };
}

describe('phase 83 ingest', () => {
  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_INGEST;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('refuses ingest unless the experimental flag is set', async () => {
    const refused = await runCli(['ingest', fixture('npm-audit.json')]);
    expect(refused.code).toBe(2);
    expect(refused.err).toContain('FS-E012');
    expect(refused.err).toContain('FULLSHIELD_EXPERIMENTAL_INGEST');
    expect(refused.out).toBe('');
  });

  it('merges one CVE reported by npm audit and OSV-Scanner', async () => {
    const loaded = await ingestLocalFiles([fixture('npm-audit.json'), fixture('osv-scanner.json')]);
    expect(loaded.errors).toEqual([]);
    expect(loaded.findings).toHaveLength(1);
    const row = loaded.findings[0];
    expect(row?.sources).toEqual(['npm-audit', 'osv-scanner']);
    expect(row?.source).toBe('npm-audit');
    expect(row?.severity).toBe('high');
    expect(row?.externalSeverity).toBe('high');
    expect(row?.module).toBe('deps');
    expect(row?.externalRuleIds).toEqual(expect.arrayContaining(['CVE-2024-99999', 'GHSA-FX00-0000-0000']));
    expect(row).not.toHaveProperty('fullshieldPriority');
  });

  it('does not merge a different advisory or a different version', async () => {
    const other = await ingestLocalFiles([fixture('npm-audit.json'), fixture('npm-other.json')]);
    expect(other.findings).toHaveLength(2);
    const versions = await ingestLocalFiles([fixture('npm-audit.json'), fixture('osv-other-version.json')]);
    expect(versions.findings).toHaveLength(2);
  });

  it('merges Semgrep SQLi with SAST-SQLI-001 on a nearby line and keeps evidence', async () => {
    const loaded = await ingestLocalFiles([
      fixture('semgrep-sqli.json'),
      fixture('fullshield-sqli.sarif.json'),
    ]);
    expect(loaded.findings).toHaveLength(1);
    const row = loaded.findings[0];
    expect(row?.ruleId).toBe('SAST-SQLI-001');
    expect(row?.externalRuleId).toBe('fixture.sqli');
    expect(row?.sources).toEqual(['FullShield', 'semgrep']);
    expect(row?.severity).toBe('high');
    expect(row?.cwe).toBe('CWE-89');
    expect(row?.reachability).toBe('reachable');
    expect(row?.sinkClass).toBe('sql');
    expect(row?.routeExposure).toBe('unauthenticated');
    expect(row).not.toHaveProperty('fullshieldPriority');
  });

  it('does not merge a distant line or a different CWE', async () => {
    const far = await ingestLocalFiles([fixture('semgrep-far.json'), fixture('fullshield-sqli.sarif.json')]);
    expect(far.findings).toHaveLength(2);
    const xss = await ingestLocalFiles([fixture('semgrep-xss.json'), fixture('fullshield-sqli.sarif.json')]);
    expect(xss.findings).toHaveLength(2);
  });

  it('merges equal SARIF partialFingerprints and keeps a different fingerprint', async () => {
    const same = await ingestLocalFiles([fixture('sarif-fp-a.sarif.json'), fixture('sarif-fp-b.sarif.json')]);
    expect(same.findings).toHaveLength(1);
    expect(same.findings[0]?.sources).toEqual(['ToolA', 'ToolB']);
    const different = await ingestLocalFiles([
      fixture('sarif-fp-b.sarif.json'),
      fixture('sarif-fp-c.sarif.json'),
    ]);
    expect(different.findings).toHaveLength(2);
  });

  it('does not raise severity and does not invent evidence', async () => {
    const warning = await ingestLocalFiles([fixture('semgrep-warning.json')]);
    expect(warning.findings[0]?.severity).toBe('medium');
    expect(warning.findings[0]?.externalSeverity).toBe('WARNING');
    const moderate = await ingestLocalFiles([fixture('npm-moderate.json')]);
    expect(moderate.findings[0]?.severity).toBe('medium');
    expect(moderate.findings[0]?.externalSeverity).toBe('moderate');
    expect(moderate.findings[0]?.severity).not.toBe('high');
    const plain = await ingestLocalFiles([fixture('sarif-plain.sarif.json')]);
    expect(plain.findings[0]?.reachability).toBeUndefined();
    expect(plain.findings[0]?.sinkClass).toBeUndefined();
    expect(plain.findings[0]?.routeExposure).toBeUndefined();
    expect(plain.findings[0]).not.toHaveProperty('fullshieldPriority');
  });

  it('names the bad file and still ingests the others', async () => {
    const loaded = await ingestLocalFiles([
      fixture('malformed.json'),
      fixture('npm-audit.json'),
      fixture('unknown.json'),
      fixture('bad-sarif.json'),
    ]);
    expect(loaded.findings).toHaveLength(1);
    expect(loaded.errors.map((error) => error.file)).toEqual([
      fixture('malformed.json'),
      fixture('unknown.json'),
      fixture('bad-sarif.json'),
    ]);
    expect(loaded.errors[0]?.schemaError.length).toBeGreaterThan(0);
    expect(loaded.errors[1]?.schemaError).toContain('unrecognized');
    expect(loaded.errors[2]?.schemaError).toContain('runs');
  });

  it('prints JSON, the Phase 47 console row, and one SARIF run per tool plus FullShield', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_INGEST = '1';
    const json = await runCli([
      'ingest',
      fixture('npm-audit.json'),
      fixture('osv-scanner.json'),
      '--json',
    ]);
    expect(json.code).toBe(0);
    expect(json.err).toBe('');
    const doc = JSON.parse(json.out) as { findings: Array<{ sources?: string[] }> };
    expect(doc.findings).toHaveLength(1);
    expect(doc.findings[0]?.sources).toEqual(['npm-audit', 'osv-scanner']);

    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ingest-'));
    dirs.push(dir);
    const sarifPath = join(dir, 'out.sarif');
    const sarifRun = await runCli([
      'ingest',
      fixture('npm-audit.json'),
      fixture('osv-scanner.json'),
      '--json',
      '--sarif',
      sarifPath,
    ]);
    expect(sarifRun.code).toBe(0);
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8')) as {
      runs: Array<{ tool: { driver: { name: string } } }>;
    };
    expect(validateSarif21(sarif)).toEqual([]);
    const names = sarif.runs.map((run) => run.tool.driver.name);
    expect(names).toEqual(['npm-audit', 'osv-scanner', 'FullShield']);

    const consoleRun = await runCli([
      'ingest',
      fixture('semgrep-sqli.json'),
      fixture('fullshield-sqli.sarif.json'),
    ]);
    expect(consoleRun.code).toBe(0);
    expect(consoleRun.out).toContain('SAST-SQLI-001');
  });

  it('does not attach ingest fields on a default scan', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ingest-scan-'));
    dirs.push(dir);
    await writeFile(join(dir, 'index.js'), 'const value = 1;\nconsole.log(value);\n');
    const result = await scan({ cwd: dir, offline: true, modules: ['secrets'] });
    expect(result.findings.every((finding) => finding.sources === undefined)).toBe(true);
    expect(result.findings.every((finding) => finding.externalRuleId === undefined)).toBe(true);
    expect(result.findings.every((finding) => !Object.hasOwn(finding, 'fullshieldPriority'))).toBe(true);
  });
});
