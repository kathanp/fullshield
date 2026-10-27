import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';

const vulnerableApp = join(import.meta.dirname, '../../fixtures/vulnerable-app');
const dirs: string[] = [];

function stable(findings: readonly Finding[]): string {
  const rows = findings.map((finding) => [finding.ruleId, finding.file ?? '', finding.line ?? 0, finding.severity]);
  rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return JSON.stringify(rows);
}

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  delete process.env.FULLSHIELD_PARSE_CACHE_DIR;
  delete process.env.FULLSHIELD_PARSE_WORKERS;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 549 persistent parse cache', () => {
  it('reuses a warm PERF2 scan and recovers from a corrupt cache file', async () => {
    const cache = await mkdtemp(join(tmpdir(), 'fs-549-'));
    dirs.push(cache);
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    process.env.FULLSHIELD_PARSE_CACHE_DIR = cache;
    process.env.FULLSHIELD_PARSE_WORKERS = '1';
    const cold = await scan({ cwd: vulnerableApp, offline: true });
    const warm = await scan({ cwd: vulnerableApp, offline: true });
    expect(stable(warm.findings)).toBe(stable(cold.findings));
    const astRoot = join(cache, 'ast');
    const shards = await readdir(astRoot).catch(() => [] as string[]);
    expect(shards.length).toBeGreaterThan(0);
    for (const shard of shards) {
      const files = await readdir(join(astRoot, shard));
      await Promise.all(files.map((file) => writeFile(join(astRoot, shard, file), '{')));
    }
    const rebuilt = await scan({ cwd: vulnerableApp, offline: true });
    expect(stable(rebuilt.findings)).toBe(stable(cold.findings));
  });
});
