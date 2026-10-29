import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { ADOPT_FLAG, adoptOutput, digestFile, stackNote } from '../../../src/cli/adopt.js';
import { createProgram } from '../../../src/cli/program.js';

const stacks = ['express', 'nest', 'next', 'fastify', 'hono'] as const;

afterEach(() => {
  delete process.env[ADOPT_FLAG];
});

describe('phase 569 adopt', () => {
  it('throws before a read or a write when the flag is off', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    expect(() => adoptOutput(cwd, { tour: true, force: false })).toThrow(/FULLSHIELD_EXPERIMENTAL_ADOPT/);
    expect(() => digestFile(join(cwd, 'missing.json'))).toThrow(/FULLSHIELD_EXPERIMENTAL_ADOPT/);
    expect(() => readFileSync(join(cwd, 'fullshield.stack.md'), 'utf8')).toThrow();
  });

  it('prints the tour and writes no file', () => {
    process.env[ADOPT_FLAG] = '1';
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    const lines = adoptOutput(cwd, { tour: true, force: false });
    expect(lines).toEqual([
      '1. fullshield scan',
      '2. fullshield fix --dry-run',
      '3. fullshield init --ci',
      '4. This tour does not run project tests.',
      '5. This tour does not scan the home directory.',
    ]);
    expect(() => readFileSync(join(cwd, 'fullshield.stack.md'), 'utf8')).toThrow();
  });

  it('writes a monitor note and does not suppress a finding', () => {
    process.env[ADOPT_FLAG] = '1';
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    const lines = adoptOutput(cwd, { tour: false, stack: 'express', force: false });
    const note = readFileSync(join(cwd, 'fullshield.stack.md'), 'utf8');
    expect(note).toBe(stackNote('express'));
    expect(note).toContain('mode: monitor');
    expect(note).toContain('does not suppress a finding');
    expect(lines[0]).toContain('fullshield.stack.md');
    expect(adoptOutput(cwd, { tour: false, stack: 'express', force: false })[0]).toContain('Nothing to write');
    for (const name of stacks) {
      const file = readFileSync(join(process.cwd(), 'templates', 'stacks', `${name}.md`), 'utf8');
      expect(file).toBe(stackNote(name));
    }
  });

  it('writes nothing for an unknown stack', () => {
    process.env[ADOPT_FLAG] = '1';
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    expect(() => adoptOutput(cwd, { tour: false, stack: 'python', force: false })).toThrow(/unknown stack/);
    expect(() => readFileSync(join(cwd, 'fullshield.stack.md'), 'utf8')).toThrow();
  });

  it('prints only npm ids from a local array', () => {
    process.env[ADOPT_FLAG] = '1';
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    const file = join(cwd, 'osv.json');
    writeFileSync(file, JSON.stringify([
      { id: 'GHSA-2', ecosystem: 'npm' },
      { id: 'PY-1', ecosystem: 'PyPI' },
      { id: 'GHSA-1', ecosystem: 'npm' },
      { id: '', ecosystem: 'npm' },
    ]));
    expect(digestFile(file)).toEqual(['GHSA-1', 'GHSA-2']);
    writeFileSync(file, '{');
    expect(() => digestFile(file)).toThrow(/not JSON/);
    writeFileSync(file, '{}');
    expect(() => digestFile(file)).toThrow(/must be an array/);
  });

  it('refuses the tour command before init when the flag is off', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'fs-adopt-'));
    const err: string[] = [];
    const program = createProgram({ out: () => undefined, err: (line) => err.push(line) });
    await program.parseAsync(['node', 'fullshield', 'init', cwd, '--tour']);
    expect(err.join('\n')).toContain('FS-E025');
    expect(() => readFileSync(join(cwd, 'fullshield.config.json'), 'utf8')).toThrow();
  });
});
