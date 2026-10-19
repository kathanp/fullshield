import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { lastParseCounts } from '../../../src/core/shared-ast.js';
import { takeLastTaintWalk } from '../../../src/modules/sast/lazy-taint.js';

const vulnerableApp = join(import.meta.dirname, '../../fixtures/vulnerable-app');
const cleanApp = join(import.meta.dirname, '../../fixtures/clean-app');
const dirs: string[] = [];

function stable(findings: readonly Finding[]): string {
  const rows = findings.map((finding) => ({
    ruleId: finding.ruleId,
    file: finding.file ?? '',
    line: finding.line ?? 0,
    severity: finding.severity,
    confidence: finding.confidence,
    message: finding.message,
    snippet: finding.snippet ?? '',
  }));
  rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return JSON.stringify(rows);
}

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  delete process.env.FULLSHIELD_CALL_GRAPH_DIR;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 78 steps 3-6', () => {
  it('parses each source file at most once when the flag is on', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-perf2-parse-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'src'));
    await writeFile(join(cwd, 'src', 'a.js'), 'function add(a, b) { return a + b; }\n');
    await writeFile(join(cwd, 'src', 'b.js'), 'const { add } = require("./a");\nfunction go(req) { return add(req.query.id, 1); }\n');
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    await scan({ cwd, offline: true });
    const counts = lastParseCounts();
    expect(counts.get('src/a.js')).toBe(1);
    expect(counts.get('src/b.js')).toBe(1);
  });

  it('matches sorted findings with the flag off on vulnerable-app and clean-app', async () => {
    const vulnOff = await scan({ cwd: vulnerableApp, offline: true });
    const cleanOff = await scan({ cwd: cleanApp, offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    const vulnOn = await scan({ cwd: vulnerableApp, offline: true });
    const cleanOn = await scan({ cwd: cleanApp, offline: true });
    expect(stable(vulnOn.findings)).toBe(stable(vulnOff.findings));
    expect(cleanOn.findings).toEqual([]);
    expect(cleanOff.findings).toEqual([]);
  });

  it('discards a corrupt call-graph cache entry and keeps the same dependency usage', async () => {
    const cache = await mkdtemp(join(tmpdir(), 'fs-callgraph-'));
    dirs.push(cache);
    process.env.FULLSHIELD_CALL_GRAPH_DIR = cache;
    const off = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    const warm = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true });
    expect(stable(warm.findings)).toBe(stable(off.findings));
    const files = await readdir(cache);
    expect(files.length).toBeGreaterThan(0);
    await Promise.all(files.map((file) => writeFile(join(cache, file), '{')));
    const rebuilt = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true });
    expect(stable(rebuilt.findings)).toBe(stable(off.findings));
  });

  it('walks a source file and its import, and does not walk an unrelated file', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-perf2-lazy-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'src'));
    await writeFile(
      join(cwd, 'src', 'lib.js'),
      'function build(id) { return "SELECT " + id; }\nmodule.exports = { build };\n',
    );
    await writeFile(
      join(cwd, 'src', 'app.js'),
      'const { build } = require("./lib");\nfunction go(req) { db.query("SELECT " + req.query.id); build(req.query.id); }\n',
    );
    await writeFile(join(cwd, 'src', 'plain.js'), 'function add(a, b) { return a + b; }\n');
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    const walked = takeLastTaintWalk();
    expect(walked).toContain('src/app.js');
    expect(walked).toContain('src/lib.js');
    expect(walked).not.toContain('src/plain.js');
  });

  it('matches sorted findings on checked-out bench apps', async () => {
    const home = process.env.FULLSHIELD_BENCH_DIR ?? join(homedir(), 'fullshield-bench');
    const names = ['NodeGoat', 'juice-shop', 'dvna', 'goof', 'vulnerable-node'];
    for (const name of names) {
      const cwd = join(home, name);
      if (!existsSync(join(cwd, 'package.json'))) continue;
      delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
      const off = await scan({ cwd, offline: true });
      process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
      const on = await scan({ cwd, offline: true });
      expect(stable(on.findings)).toBe(stable(off.findings));
    }
  }, 600_000);
});
