import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { logLeakEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_LOGLEAK';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-logleak-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_LOGLEAK', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(logLeakEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(logLeakEnabled()).toBe(true);
  });

  it('reports credential logs and ignores tokenCount, a non-auth body, and a redacted path', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'leak.js'),
      ['console.log(req.headers.authorization);', 'console.log(req.headers.cookie);', 'console.log(password);', 'console.log(apiKey);'].join('\n'),
    );
    await writeFile(join(cwd, 'count.js'), 'console.log(tokenCount);\nconsole.log(req.body);\n');
    await writeFile(join(cwd, 'auth.js'), "app.post('/login', () => { console.log(req.body); });\n");
    await writeFile(
      join(cwd, 'redacted.js'),
      "const logger = pino({ redact: ['req.headers.authorization'] });\nlogger.info(req.headers.authorization);\n",
    );
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const hits = result.findings.filter((f) => f.ruleId === 'SAST-LOGLEAK-001');
    expect(hits.filter((f) => f.file === 'leak.js').length).toBeGreaterThanOrEqual(4);
    expect(hits.filter((f) => f.file === 'auth.js')).toHaveLength(1);
    expect(hits.filter((f) => f.file === 'count.js' || f.file === 'redacted.js')).toEqual([]);
    expect(hits.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'leak.js'), 'console.log(password);\n');
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-LOGLEAK-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'leak.js'), 'console.info(secret);\n');
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-LOGLEAK-001')).toBe(true);
  });
});
