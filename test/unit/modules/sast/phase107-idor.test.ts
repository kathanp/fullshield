import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { failsCi } from '../../../../src/core/finding.js';
import { idorEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_IDOR';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-idor-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_IDOR', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(idorEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(idorEnabled()).toBe(true);
  });

  it('hints when a handler loads by id without an owner check, and never fails CI', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'open.js'),
      "app.get('/users/:id', (req, res) => { const row = User.findById(req.params.id); res.json(row); });\n",
    );
    await writeFile(
      join(cwd, 'owned.js'),
      "app.get('/users/:id', (req, res) => { const row = User.findById(req.params.id); if (row.owner !== req.user.id) return; res.json(row); });\n",
    );
    await writeFile(
      join(cwd, 'staff.js'),
      "app.get('/users/:id', admin, (req, res) => { User.findById(req.params.id); });\n",
    );
    await writeFile(
      join(cwd, 'helper.js'),
      "app.get('/orders/:id', (req, res) => { loadOrder(req.params.id); });\nfunction loadOrder(id) { return Order.findById(id); }\n",
    );
    await writeFile(
      join(cwd, 'helper-owned.js'),
      "app.get('/orders/:id', (req, res) => { loadOrder(req.params.id); });\nfunction loadOrder(id) { const row = Order.findById(id); if (row.owner !== req.user.id) return row; }\n",
    );
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const hits = result.findings.filter((f) => f.ruleId === 'SAST-IDOR-001');
    expect(hits.map((f) => f.file).sort()).toEqual(['helper.js', 'open.js']);
    expect(hits.every((f) => f.source === 'rule' && f.severity === 'low' && f.confidence === 'low')).toBe(true);
    expect(failsCi(hits[0]!, 'info')).toBe(false);
    expect(failsCi(hits[0]!, 'low')).toBe(false);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'open.js'), "app.get('/orders/:id', (req, res) => { Order.findByPk(req.params.id); });\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-IDOR-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'open.js'), "app.get('/orders/:id', (req, res) => { db.findUnique({ where: { id: req.params.id } }); });\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-IDOR-001')).toBe(true);
  });
});
