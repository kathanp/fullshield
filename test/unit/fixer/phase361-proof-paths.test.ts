import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { unifiedDiff } from '../../../src/fixer/diff.js';
import { openVerifiedFixPr } from '../../../src/fixer/pull-request.js';
import { proveFixes, verifyFixInCopy } from '../../../src/fixer/temp-verify.js';
import { proveUpgrade } from '../../../src/fixer/upgrade-proof.js';

const dirs: string[] = [];
const savedPath = process.env.PATH;

afterEach(async () => {
  process.env.PATH = savedPath;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function scratch(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fs-proof-'));
  dirs.push(dir);
  return dir;
}

async function commandOnPath(dir: string, name: string, body: string): Promise<void> {
  const bin = join(dir, 'bin');
  await mkdir(bin, { recursive: true });
  if (process.platform === 'win32') {
    await writeFile(join(bin, `${name}.cmd`), `@echo off\r\n${body}\r\n`, 'utf8');
  } else {
    const file = join(bin, name);
    await writeFile(file, `#!/bin/sh\n${body}\n`, 'utf8');
    await chmod(file, 0o755);
  }
  process.env.PATH = `${bin}${process.platform === 'win32' ? ';' : ':'}${savedPath ?? ''}`;
}

describe('fix proof paths', () => {
  it('treats a failed install as an upgrade that breaks tests', async () => {
    const status = await proveUpgrade({
      spec: 'left-pad@1.0.0',
      install: () => Promise.resolve(false),
      test: () => Promise.resolve(true),
    });
    expect(status).toBe('upgrade-breaks-tests');
  });

  it('uses the npm on PATH when no installer is injected', async () => {
    const dir = await scratch();
    await commandOnPath(dir, 'npm', 'exit 0');
    const safe = await proveUpgrade({ spec: 'left-pad@1.0.0' });
    expect(safe).toBe('upgrade-safe');

    await commandOnPath(dir, 'npm', 'exit 1');
    const broke = await proveUpgrade({ spec: 'left-pad@1.0.0' });
    expect(broke).toBe('upgrade-breaks-tests');
  });

  it('reports a missing npm as an upgrade that breaks tests', async () => {
    const dir = await scratch();
    process.env.PATH = dir;
    const status = await proveUpgrade({ spec: 'left-pad@1.0.0' });
    expect(status).toBe('upgrade-breaks-tests');
  });

  it('opens a pull request through gh and reports when gh is missing', async () => {
    const dir = await scratch();
    await commandOnPath(dir, 'gh', 'echo fake-pr');
    const opened = await openVerifiedFixPr({ title: 'fix one finding', body: 'temp copy' });
    expect(opened.status).toBe(0);
    expect(opened.stdout).toContain('fake-pr');

    process.env.PATH = dir;
    const missing = await openVerifiedFixPr({ title: 'fix one finding', body: 'temp copy' });
    expect(missing.status).toBe(127);
    expect(missing.stdout).toBe('');
  });

  it('keeps not-fixed when the temp copy still has the finding', async () => {
    const cwd = await scratch();
    const source = 'const token = Math.random().toString(36);\n';
    await writeFile(join(cwd, 'a.js'), source, 'utf8');
    const status = await verifyFixInCopy({
      cwd,
      file: 'a.js',
      diff: unifiedDiff('a.js', source, source),
      ruleId: 'SAST-CRYPTO-001',
    });
    expect(status).toBe('not-fixed');
    expect(await readFile(join(cwd, 'a.js'), 'utf8')).toBe(source);
  });

  it('skips project tests when the caller turns them off', async () => {
    const cwd = await scratch();
    const source = 'const token = Math.random().toString(36);\n';
    const fixed = "const crypto = require('crypto');\nconst token = crypto.randomUUID();\n";
    await writeFile(join(cwd, 'a.js'), source, 'utf8');
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ scripts: { test: 'node -e "process.exit(1)"' } }), 'utf8');
    const status = await verifyFixInCopy({
      cwd,
      file: 'a.js',
      diff: unifiedDiff('a.js', source, fixed),
      ruleId: 'SAST-CRYPTO-001',
      runTests: false,
    });
    expect(status).toBe('fixed');
  });

  it('proves a crypto patch from a scan of the temp app', async () => {
    const cwd = await scratch();
    await writeFile(join(cwd, 'a.js'), 'const token = Math.random().toString(36);\n', 'utf8');
    const rows = await proveFixes(cwd);
    expect(rows).toEqual([{ ruleId: 'SAST-CRYPTO-001', status: 'fixed' }]);
    expect(await readFile(join(cwd, 'a.js'), 'utf8')).toContain('Math.random()');
  });

  it('accepts a windows-style relative path and a package file that is not json', async () => {
    const cwd = await scratch();
    const source = 'const token = Math.random().toString(36);\n';
    const fixed = "const crypto = require('crypto');\nconst token = crypto.randomUUID();\n";
    await mkdir(join(cwd, 'sub'));
    await writeFile(join(cwd, 'sub', 'a.js'), source, 'utf8');
    await writeFile(join(cwd, 'package.json'), '{', 'utf8');
    const status = await verifyFixInCopy({
      cwd,
      file: 'sub\\a.js',
      diff: unifiedDiff('sub/a.js', source, fixed),
      ruleId: 'SAST-CRYPTO-001',
    });
    expect(status).toBe('fixed');
    expect(await readFile(join(cwd, 'sub', 'a.js'), 'utf8')).toBe(source);
  });
});
