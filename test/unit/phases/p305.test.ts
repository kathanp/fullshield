import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { analyzeCli, enabled, FLAG, scanTreeForCli } from '../../../src/phases/p305.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 305 cli', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeCli("program.option('--branch <branch>');\nexec('deploy ' + program.opts().branch);").findings).toEqual([]);
  });

  it('reports a low command finding and skips execFile, sql, and libraries', () => {
    process.env[FLAG] = '1';
    const hit = analyzeCli("const { program } = require('commander');\nprogram.option('--branch <branch>');\nexec('deploy ' + program.opts().branch);");
    expect(hit.findings[0]).toMatchObject({ origin: 'cli', severity: 'low', sinkClass: 'cmdi' });
    expect(analyzeCli("program.option('--branch <branch>');\nexecFile('git', ['log', '--', program.opts().branch]);").findings).toEqual([]);
    expect(analyzeCli("program.option('--q <q>');\ndb.query('select ' + program.opts().q);").findings).toEqual([]);
    expect(analyzeCli('function lib(x) { return x; }').findings).toEqual([]);
    expect(scanTreeForCli(join(import.meta.dirname, '../../..', 'test/fixtures/clean-app'))).toEqual([]);
  });

  it('does not walk a tree when the flag is off', () => {
    expect(scanTreeForCli(join(import.meta.dirname, '../../..', 'test/fixtures/clean-app'))).toEqual([]);
  });

  it('treats a bin package as a cli and classifies eval, path, and argv', () => {
    process.env[FLAG] = '1';
    expect(analyzeCli('???').findings).toEqual([]);
    expect(analyzeCli('eval(process.argv[1]);', { bin: true, file: 'bin.js' }).findings[0]).toMatchObject({ sinkClass: 'eval', file: 'bin.js' });
    expect(analyzeCli("program.command('a');\nreadFile(program.opts().file);").findings[0]?.sinkClass).toBe('path');
    expect(analyzeCli("program.command('a');\nexec();").findings).toEqual([]);
    expect(analyzeCli("program.command('a');\nexec('fixed');").findings).toEqual([]);
    const root = join(import.meta.dirname, '.tmp-p305');
    rmSync(root, { recursive: true, force: true });
    try {
      mkdirSync(join(root, 'node_modules'), { recursive: true });
      mkdirSync(join(root, 'test'), { recursive: true });
      mkdirSync(join(root, 'tests'), { recursive: true });
      mkdirSync(join(root, 'nested'), { recursive: true });
      mkdirSync(join(root, 'lib'), { recursive: true });
      writeFileSync(join(root, 'node_modules', 'skip.js'), 'exec(process.argv[1]);');
      writeFileSync(join(root, 'test', 'skip.js'), 'exec(process.argv[1]);');
      writeFileSync(join(root, 'tests', 'skip.js'), 'exec(process.argv[1]);');
      writeFileSync(join(root, 'note.txt'), 'exec(process.argv[1]);');
      writeFileSync(join(root, 'package.json'), JSON.stringify({ bin: 'cli.js' }));
      writeFileSync(join(root, 'cli.js'), "const commander = require('commander');\nprogram.command('x');\nnew Command();\neval(program.opts().code);\nreadFileSync(yargs.argv._);\nexecSync(process.argv[2]);\n(0, exec)(process.argv);\nspawn(program.opts().x);\n");
      writeFileSync(join(root, 'plain.js'), 'exec(process.argv[1]);');
      writeFileSync(join(root, 'nested', 'package.json'), '{');
      writeFileSync(join(root, 'nested', 'lib.ts'), "const yargs = require('yargs');\nexec(yargs.argv._);\n");
      writeFileSync(join(root, 'lib', 'package.json'), JSON.stringify({ name: 'lib' }));
      writeFileSync(join(root, 'lib', 'main.js'), "program.option('--a');\nreadFile(program.opts().a);\n");
      const findings = scanTreeForCli(root);
      expect(findings.some((finding) => finding.file.includes('node_modules') || finding.file.includes(`${join('test', 'skip')}`))).toBe(false);
      expect(findings.map((finding) => finding.sinkClass)).toEqual(expect.arrayContaining(['eval', 'path', 'cmdi']));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
