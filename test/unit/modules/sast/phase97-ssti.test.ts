import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { sstiEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SSTI';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-ssti-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_SSTI', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(sstiEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(sstiEnabled()).toBe(true);
  });

  it('reports a tainted template source and ignores data arguments and unknown engines', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'app.js'),
      [
        'ejs.render(req.query.tpl);',
        "ejs.render('hello <%= name %>', req.query);",
        'unknownEngine.render(req.query.tpl);',
        'new Function(req.query.code);',
      ].join('\n'),
    );
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const hits = result.findings.filter((f) => f.ruleId === 'SAST-SSTI-001');
    expect(hits.length).toBeGreaterThanOrEqual(2);
    expect(hits.every((f) => f.severity === 'critical')).toBe(true);
    expect(hits.some((f) => f.line === 2)).toBe(false);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), 'ejs.render(req.query.tpl);\n');
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-SSTI-001');
    expect(onClean.findings.filter((f) => f.ruleId === 'SAST-SSTI-001')).toEqual([]);
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), 'handlebars.compile(req.query.tpl);\n');
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-SSTI-001')).toBe(true);
  });
});
