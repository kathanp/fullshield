import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { closeAllDbHandles, trackDbHandle } from '../../../src/core/sqlite.js';
import { startDevLoop } from '../../../src/dev/index.js';

const dirs: string[] = [];
const CLEAN = `'use strict';
function handler(req, res) {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
  res.end('ok');
}
`;
const VULN = `'use strict';
function handler(req, res) {
  db.query('SELECT * FROM users WHERE id = ' + req.query.id);
  res.end('ok');
}
`;
const VULN_SHIFTED = `
${VULN}`;

async function tempProject(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-dev-'));
  dirs.push(dir);
  return dir;
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

async function untilLines(lines: string[], from: number, count: number): Promise<string[]> {
  const start = Date.now();
  while (Date.now() - start < 5000) {
    if (lines.length >= from + count) return lines.slice(from);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return lines.slice(from);
}

describe('phase 88 developer loop', () => {
  const sessions: Array<{ close(): Promise<void> }> = [];
  let fetchImpl: typeof fetch | undefined;

  afterEach(async () => {
    for (const session of sessions.splice(0)) await session.close();
    closeAllDbHandles();
    if (fetchImpl !== undefined) globalThis.fetch = fetchImpl;
    fetchImpl = undefined;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('refuses dev without FULLSHIELD_EXPERIMENTAL_DEV', async () => {
    const dir = await tempProject();
    const result = await runCli(['dev', dir]);
    expect(result.code).toBe(2);
    expect(result.err).toContain('FULLSHIELD_EXPERIMENTAL_DEV');
    await expect(startDevLoop({ cwd: dir, out() {} })).rejects.toThrow(/FULLSHIELD_EXPERIMENTAL_DEV/);
  });

  it('prints one new SQLi line, then one resolved line', async () => {
    const dir = await tempProject();
    await mkdir(join(dir, 'src'));
    await writeFile(join(dir, 'src', 'app.js'), CLEAN);
    process.env.FULLSHIELD_EXPERIMENTAL_DEV = '1';
    const sigintBefore = new Set(process.listeners('SIGINT'));
    const lines: string[] = [];
    const session = await startDevLoop({ cwd: dir, out: (line) => lines.push(line) });
    sessions.push(session);
    expect(lines).toEqual([]);

    await writeFile(join(dir, 'src', 'app.js'), VULN);
    const added = await untilLines(lines, 0, 1);
    expect(added).toEqual(['new SAST-SQLI-001 src/app.js']);

    await writeFile(join(dir, 'src', 'app.js'), VULN_SHIFTED);
    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(lines).toEqual(['new SAST-SQLI-001 src/app.js']);

    await writeFile(join(dir, 'src', 'app.js'), CLEAN);
    const resolved = await untilLines(lines, 1, 1);
    expect(resolved).toEqual(['resolved SAST-SQLI-001 src/app.js']);

    let dbClosed = false;
    trackDbHandle({ close() { dbClosed = true; } });
    const ours = process.listeners('SIGINT').filter((listener) => !sigintBefore.has(listener));
    expect(ours).toHaveLength(1);
    ours[0]?.('SIGINT');
    expect(dbClosed).toBe(true);
    await writeFile(join(dir, 'src', 'app.js'), VULN);
    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(lines).toEqual(['new SAST-SQLI-001 src/app.js', 'resolved SAST-SQLI-001 src/app.js']);
  });

  it('polls on Linux and rescans reverse dependents', async () => {
    const dir = await tempProject();
    await mkdir(join(dir, 'src'));
    await writeFile(
      join(dir, 'src', 'lib.js'),
      `'use strict';
function build(id) {
  return id;
}
module.exports = { build };
`,
    );
    await writeFile(
      join(dir, 'src', 'app.js'),
      `'use strict';
const { build } = require('./lib');
function handler(req) {
  build(req.query.id);
}
`,
    );
    process.env.FULLSHIELD_EXPERIMENTAL_DEV = '1';
    const lines: string[] = [];
    const session = await startDevLoop({
      cwd: dir,
      out: (line) => lines.push(line),
      platform: 'linux',
      pollIntervalMs: 50,
    });
    sessions.push(session);
    await writeFile(
      join(dir, 'src', 'lib.js'),
      `'use strict';
function build(id) {
  db.query('SELECT * FROM t WHERE id = ' + id);
}
module.exports = { build };
`,
    );
    const added = await untilLines(lines, 0, 1);
    expect(added).toEqual(['new SAST-SQLI-001 src/lib.js']);
  });

  it('does not call OSV when a source file is saved', async () => {
    const dir = await tempProject();
    await mkdir(join(dir, 'src'));
    await writeFile(join(dir, 'src', 'app.js'), CLEAN);
    const version = `9.9.${Date.now() % 100000}`;
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'probe', private: true, dependencies: { 'fullshield-phase88-probe': version } }),
    );
    let osvCalls = 0;
    fetchImpl = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input).includes('api.osv.dev')) osvCalls += 1;
      return new Response(JSON.stringify({ results: [{ vulns: [] }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    process.env.FULLSHIELD_EXPERIMENTAL_DEV = '1';
    const session = await startDevLoop({ cwd: dir, out() {}, platform: 'linux', pollIntervalMs: 50 });
    sessions.push(session);
    expect(osvCalls).toBeGreaterThan(0);
    const cache = join(homedir(), '.cache', 'fullshield', 'osv', `fullshield-phase88-probe@${version}.json`);
    await rm(cache, { force: true });
    const afterStart = osvCalls;
    await writeFile(join(dir, 'src', 'app.js'), VULN);
    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(osvCalls).toBe(afterStart);
    const nextVersion = `${version}-b`;
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'probe', private: true, dependencies: { 'fullshield-phase88-probe': nextVersion } }),
    );
    const start = Date.now();
    while (osvCalls === afterStart && Date.now() - start < 5000) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(osvCalls).toBeGreaterThan(afterStart);
    await rm(cache, { force: true });
    await rm(join(homedir(), '.cache', 'fullshield', 'osv', `fullshield-phase88-probe@${nextVersion}.json`), { force: true });
  });
});
