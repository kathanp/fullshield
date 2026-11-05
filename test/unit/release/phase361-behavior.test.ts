import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { writeAgentConfig } from '../../../src/cli/agent-init.js';
import { failsCi, type Finding } from '../../../src/core/finding.js';
import { scan } from '../../../src/core/engine.js';
import { applyRecordedEvidence } from '../../../src/evidence/record.js';
import { unifiedDiff } from '../../../src/fixer/diff.js';
import { verifyFixInCopy } from '../../../src/fixer/temp-verify.js';
import { reviewedVulnFunctions } from '../../../src/modules/deps/vuln-functions.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_PARSE_CACHE_DIR;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function findJson(dir: string): Promise<string | undefined> {
  const { readdir } = await import('node:fs/promises');
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await findJson(path);
      if (nested !== undefined) {return nested;}
    } else if (entry.name.endsWith('.json')) {
      return path;
    }
  }
  return undefined;
}

function finding(file: string): Finding {
  return {
    id: '1',
    ruleId: 'SAST-EVAL-001',
    module: 'sast',
    title: 'eval',
    message: 'eval',
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    remediation: 'remove it',
  };
}

describe('3.6.1 scan behavior', () => {
  it('does not fail CI when gate is false', () => {
    expect(failsCi({ ...finding('a.js'), gate: false }, 'low')).toBe(false);
    expect(failsCi(finding('a.js'), 'low')).toBe(true);
  });

  it('downgrades a finding whose file was not recorded', () => {
    const [kept, dropped] = applyRecordedEvidence(
      [finding('ran.js'), finding('idle.js')],
      ['ran.js'],
    );
    expect(kept?.severity).toBe('high');
    expect(dropped).toMatchObject({ severity: 'info', gate: false });
  });

  it('writes a versioned parse cache and still scans after a corrupt file', async () => {
    const cache = await mkdtemp(join(tmpdir(), 'fs-parse-'));
    const cwd = await mkdtemp(join(tmpdir(), 'fs-app-'));
    dirs.push(cache, cwd);
    process.env.FULLSHIELD_PARSE_CACHE_DIR = cache;
    const { parseCacheEnabled, parseCacheDir } = await import('../../../src/core/parse-pool.js');
    expect(parseCacheEnabled(), parseCacheDir()).toBe(true);
    await writeFile(join(cwd, 'a.js'), 'function go(req) { eval(req.body.code); }\n', 'utf8');
    const first = await scan({ cwd, offline: true, modules: ['sast'] });
    expect(first.findings.some((item) => item.ruleId === 'SAST-EVAL-001')).toBe(true);
    const shard = await findJson(cache);
    expect(shard).toBeDefined();
    await writeFile(shard ?? '', '{', 'utf8');
    const second = await scan({ cwd, offline: true, modules: ['sast'] });
    expect(second.findings.some((item) => item.ruleId === 'SAST-EVAL-001')).toBe(true);
  });

  it('checks a fix in a temp copy and leaves the source file unchanged', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-fix-'));
    dirs.push(cwd);
    const source = 'function go(req) { eval(req.body.code); }\n';
    await writeFile(join(cwd, 'a.js'), source, 'utf8');
    const diff = unifiedDiff('a.js', source, 'function go(req) { return req.body.code; }\n');
    const status = await verifyFixInCopy({ cwd, file: 'a.js', diff, ruleId: 'SAST-EVAL-001' });
    expect(status).toBe('fixed');
    expect(await readFile(join(cwd, 'a.js'), 'utf8')).toBe(source);
  });

  it('ignores an uncited vuln-function row and writes the Cursor agent files', async () => {
    expect(reviewedVulnFunctions({
      rows: [{ osvId: 'X', package: 'left-pad', symbol: 'parse', source: 'https://example.invalid/x', reviewed: false }],
    })).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fs-agent-'));
    dirs.push(cwd);
    const written = await writeAgentConfig(cwd, 'cursor');
    expect(written).toContain('.cursor/rules/fullshield.mdc');
    const rule = await readFile(join(cwd, '.cursor', 'rules', 'fullshield.mdc'), 'utf8');
    expect(rule).toContain('check_diff');
    expect(rule).toContain('verified_fix');
  });
});
