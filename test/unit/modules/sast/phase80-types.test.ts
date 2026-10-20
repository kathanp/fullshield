import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import type { Finding } from '../../../../src/core/finding.js';
import { renderJsonReport } from '../../../../src/reporters/json.js';
import { typeScriptLoader } from '../../../../src/modules/sast/type-receivers.js';

const app = join(import.meta.dirname, '../../../fixtures/types-app');
const clean = join(import.meta.dirname, '../../../fixtures/clean-app');
const root = join(import.meta.dirname, '../../../..');

function nosql(findings: readonly Finding[], file: string): Finding[] {
  return findings.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001' && finding.file?.endsWith(file));
}

function keys(findings: readonly Finding[]): string[] {
  return findings.map((finding) => `${finding.ruleId}\0${finding.file ?? ''}\0${finding.line ?? ''}`).sort();
}

describe('phase 80 type-aware receivers', () => {
  const originalLoad = typeScriptLoader.load.bind(typeScriptLoader);

  afterEach(() => {
    typeScriptLoader.load = originalLoad;
    delete process.env.FULLSHIELD_EXPERIMENTAL_TYPES;
  });

  it('keeps every receiver finding and omits suppressed when the flag is off', async () => {
    const result = await scan({ cwd: app, modules: ['sast'] });
    expect(nosql(result.findings, 'array-find.ts')).toHaveLength(1);
    expect(nosql(result.findings, 'mongoose-model.ts')).toHaveLength(1);
    expect(nosql(result.findings, 'any-receiver.ts')).toHaveLength(1);
    expect(nosql(result.findings, 'user-class.ts')).toHaveLength(1);
    expect(result.suppressed).toBeUndefined();
    const json = JSON.parse(renderJsonReport(result)) as Record<string, unknown>;
    expect(json).not.toHaveProperty('suppressed');
  });

  it('suppresses Array.find and a user class, keeps a Mongoose model and any', async () => {
    const off = await scan({ cwd: app, modules: ['sast'] });
    process.env.FULLSHIELD_EXPERIMENTAL_TYPES = '1';
    const on = await scan({ cwd: app, modules: ['sast'] });

    expect(nosql(on.findings, 'array-find.ts')).toEqual([]);
    expect(nosql(on.findings, 'user-class.ts')).toEqual([]);
    expect(nosql(on.findings, 'mongoose-model.ts')).toHaveLength(1);
    expect(nosql(on.findings, 'any-receiver.ts')).toHaveLength(1);

    const suppressed = on.suppressed ?? [];
    expect(nosql(suppressed, 'array-find.ts')).toHaveLength(1);
    expect(nosql(suppressed, 'user-class.ts')).toHaveLength(1);
    expect(suppressed.every((finding) => finding.suppressedBy === 'types')).toBe(true);
    expect(nosql(suppressed, 'mongoose-model.ts')).toEqual([]);
    expect(nosql(suppressed, 'any-receiver.ts')).toEqual([]);

    const combined = keys([...on.findings, ...suppressed]);
    expect(combined).toEqual(keys(off.findings));
    expect(on.findings.every((finding) => keys(off.findings).includes(`${finding.ruleId}\0${finding.file ?? ''}\0${finding.line ?? ''}`))).toBe(true);

    const json = JSON.parse(renderJsonReport(on)) as { suppressed: Finding[] };
    expect(json.suppressed.some((finding) => finding.file?.endsWith('array-find.ts') && finding.suppressedBy === 'types')).toBe(true);
    expect(json.suppressed.some((finding) => finding.file?.endsWith('mongoose-model.ts'))).toBe(false);
  });

  it('leaves clean-app at zero findings with the flag on', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_TYPES = '1';
    const result = await scan({ cwd: clean, modules: ['sast'] });
    expect(result.findings).toEqual([]);
  });

  it('prints FS-E012 and keeps heuristic findings when typescript cannot be loaded', async () => {
    const off = await scan({ cwd: app, modules: ['sast'] });
    typeScriptLoader.load = () => {
      const error = new Error("Cannot find package 'typescript'");
      (error as NodeJS.ErrnoException).code = 'ERR_MODULE_NOT_FOUND';
      return Promise.reject(error);
    };
    process.env.FULLSHIELD_EXPERIMENTAL_TYPES = '1';
    const on = await scan({ cwd: app, modules: ['sast'] });
    expect(keys(on.findings)).toEqual(keys(off.findings));
    expect(on.suppressed).toBeUndefined();
    expect(on.typesNotice).toMatch(/FS-E012/);
    expect(on.typesNotice).toMatch(/npm i -D typescript/);
    const json = JSON.parse(renderJsonReport(on)) as Record<string, unknown>;
    expect(json).not.toHaveProperty('suppressed');
  });

  it('falls back to heuristics when the program exceeds types.maxFiles', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs80-'));
    try {
      const configPath = join(dir, 'fullshield.config.json');
      await writeFile(configPath, JSON.stringify({ types: { maxFiles: 1 } }));
      process.env.FULLSHIELD_EXPERIMENTAL_TYPES = '1';
      const result = await scan({ cwd: app, modules: ['sast'], configPath });
      expect(nosql(result.findings, 'array-find.ts')).toHaveLength(1);
      expect(result.suppressed).toBeUndefined();
      expect(result.typesNotice).toMatch(/types\.maxFiles/);
      expect(result.typesNotice).toMatch(/heuristics/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('declares typescript as an optional peer and loads it only with import()', async () => {
    const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
    };
    expect(pkg.dependencies?.typescript).toBeUndefined();
    expect(pkg.peerDependencies?.typescript).toBeDefined();
    expect(pkg.peerDependenciesMeta?.typescript?.optional).toBe(true);
    const source = await readFile(join(root, 'src/modules/sast/type-receivers.ts'), 'utf8');
    expect(source).not.toMatch(/^import\s+(?!type\b).*['"]typescript['"]/m);
    expect(source).toMatch(/import\(['"]typescript['"]\)/);
  });
});
