import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { walkFiles } from '../../../../../src/core/fileWalker.js';
import {
  classifyInstance,
  conditionAllows,
  dynamicImportSpec,
  exportMapAllows,
  laneFindings,
  laneRows,
  reexportSpec,
  scriptReach,
  subpathExport,
  tryRequireEvidence,
  typeOnlyImport,
  workerSpec,
  type GraphCopy,
  type ImportedRoot,
} from '../../../../../src/modules/deps/npm/lane-g.js';
import { npmFlag, type NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const RULE_IDS = [
  'DEPS-GRAPH-OPTIONAL-001',
  'DEPS-PEER-MISSING-001',
  'DEPS-GRAPH-ALIAS-001',
  'DEPS-DUALPACKAGE-001',
  'DEPS-PHANTOM-002',
] as const;

const FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_OPTIONAL',
  'FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_PEER',
  'FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_ALIAS',
  'FULLSHIELD_EXPERIMENTAL_NPM_DUALPACKAGE',
  'FULLSHIELD_EXPERIMENTAL_NPM_PHANTOM_DEEP',
] as const;

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

afterEach(async () => {
  for (const flag of FLAGS) {delete process.env[flag];}
  for (const dir of dirs.splice(0)) {await rm(dir, { recursive: true, force: true });}
});

function input(cwd: string, extra: Partial<NpmDepthInput> = {}): NpmDepthInput {
  return {
    cwd,
    files: [],
    lockTexts: {},
    cacheDir: join(cwd, 'cache'),
    offline: true,
    ...extra,
  };
}

async function tempDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-lane-g-'));
  dirs.push(cwd);
  return cwd;
}

describe('lane G rows', () => {
  it('lists every rule id string in lane-g.ts', async () => {
    const source = await readFile(new URL('../../../../../src/modules/deps/npm/lane-g.ts', import.meta.url), 'utf8');
    const found = new Set([...source.matchAll(/DEPS-[A-Z0-9-]+/g)].map((match) => match[0]));
    expect([...found].sort()).toEqual([...RULE_IDS].sort());
    expect(laneRows.map((row) => row.ruleId).sort()).toEqual([...RULE_IDS].sort());
  });

  it('keeps flags off until the env value is 1', () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE;
    expect(npmFlag('NPM_GRAPH_INSTANCE')).toBe(false);
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE = '1';
    expect(npmFlag('NPM_GRAPH_INSTANCE')).toBe(true);
    delete process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE;
  });
});

describe('phase 228 classifyInstance', () => {
  const express: GraphCopy = { path: 'node_modules/express', name: 'express', requiredBy: [] };
  const roots: ImportedRoot[] = [{ name: 'express', called: true }];

  it('matches today when there is one copy', () => {
    const copies: GraphCopy[] = [
      express,
      { path: 'node_modules/qs', name: 'qs', requiredBy: ['node_modules/express'] },
    ];
    expect(classifyInstance(false, copies, roots)).toEqual(classifyInstance(true, copies, roots));
    expect(classifyInstance(false, [{ path: 'node_modules/qs', name: 'qs', requiredBy: [] }], [])[0]?.reachability).toBe(
      'not-imported',
    );
  });

  it('keeps a required nested copy reachable when the top copy is unused', () => {
    const copies: GraphCopy[] = [
      express,
      { path: 'node_modules/qs', name: 'qs', requiredBy: [], vulnerable: false },
      {
        path: 'node_modules/express/node_modules/qs',
        name: 'qs',
        requiredBy: ['node_modules/express'],
        vulnerable: true,
      },
    ];
    const flagged = classifyInstance(true, copies, roots);
    const nested = flagged.find((row) => row.path.endsWith('express/node_modules/qs'));
    const top = flagged.find((row) => row.path === 'node_modules/qs');
    expect(nested?.reachability).toBe('reachable-via-dependency');
    expect(top?.reachability).toBe('not-imported');
    const today = classifyInstance(false, copies, roots).filter((row) => row.name === 'qs');
    expect(new Set(today.map((row) => row.reachability))).toEqual(new Set(['reachable-via-dependency']));
  });
});

describe('phase 232 dynamicImportSpec', () => {
  it('counts a literal dynamic import only when the flag is on', () => {
    const source = "import('left-pad'); require.resolve('left-pad'); createRequire(import.meta.url)('left-pad');";
    expect(dynamicImportSpec(false, source).every((hit) => hit.countsAsImport === false && hit.reachability === undefined)).toBe(
      true,
    );
    expect(dynamicImportSpec(true, source).every((hit) => hit.countsAsImport && hit.literal)).toBe(true);
  });

  it('does not count a second import or a non-literal as not-imported', () => {
    const again = dynamicImportSpec(true, "import('left-pad')", ['left-pad']);
    expect(again[0]).toMatchObject({ countsAsImport: false, alreadyCounted: true });
    const open = dynamicImportSpec(true, 'import(name)');
    expect(open[0]).toMatchObject({ literal: false, countsAsImport: false, reachability: 'reachability-unknown' });
    expect(dynamicImportSpec(false, 'import(name)')[0]?.reachability).toBeUndefined();
  });
});

describe('phase 233 exportMapAllows', () => {
  it('keeps today when the flag is off or exports is absent', () => {
    expect(exportMapAllows(false, { './only': './only.js' }, 'pkg/missing')).toBe(true);
    expect(exportMapAllows(true, undefined, 'pkg/missing')).toBe(true);
    expect(exportMapAllows(true, { './only': './only.js' }, 'pkg')).toBe(true);
  });

  it('blocks a deep import the map does not allow', () => {
    const exportsField = { '.': './index.js', './sub': './sub.js' };
    expect(exportMapAllows(true, exportsField, 'pkg/sub')).toBe(true);
    expect(exportMapAllows(true, exportsField, 'pkg/missing')).toBe(false);
  });
});

describe('phase 234 conditionAllows', () => {
  it('ignores conditions when the flag is off and honors default', () => {
    expect(conditionAllows(false, { browser: './browser.js' }, 'import')).toBe(true);
    expect(conditionAllows(true, { browser: './browser.js' }, 'import')).toBe(false);
    expect(conditionAllows(true, { default: './index.js', browser: './browser.js' }, 'require')).toBe(true);
  });

  it('uses electron and react-native only when those runtimes are dependencies', () => {
    const electronOnly = { electron: './electron.js' };
    expect(conditionAllows(true, electronOnly, 'require')).toBe(false);
    const manifest = JSON.stringify({ dependencies: { electron: '30.0.0' } });
    expect(conditionAllows(true, electronOnly, 'require', { manifest })).toBe(true);
    expect(conditionAllows(true, { 'react-native': './rn.js' }, 'import', { packages: [] })).toBe(false);
    expect(conditionAllows(true, { 'react-native': './rn.js' }, 'import', { packages: ['react-native'] })).toBe(true);
  });
});

describe('phase 235 scriptReach', () => {
  it('returns the current class when the flag is off or the script does not name the bin', () => {
    const scripts = { test: 'mocha --timeout 1000' };
    expect(scriptReach(false, scripts, { mocha: 'bin/mocha.js' }, 'mocha', 'not-imported')).toBe('not-imported');
    expect(scriptReach(true, { test: 'echo hi' }, { mocha: 'bin/mocha.js' }, 'mocha')).toBe('not-imported');
    expect(scriptReach(true, scripts, { mocha: 'bin/mocha.js' }, 'mocha')).toBe('reachable-via-script');
  });
});

describe('phase 236 workerSpec', () => {
  it('counts a literal Worker or fork and ignores a bare string', () => {
    expect(workerSpec(false, "new Worker('pkg/worker.js')")[0]?.countsAsCall).toBe(false);
    const hit = workerSpec(true, "new Worker('pkg/worker.js'); child_process.fork('pkg/child.js')");
    expect(hit.every((row) => row.countsAsCall && row.name === 'pkg')).toBe(true);
    expect(workerSpec(true, "const file = 'pkg/worker.js'")).toEqual([]);
    expect(workerSpec(true, 'new Worker(file)')[0]?.reachability).toBe('reachability-unknown');
  });
});

describe('phase 237 subpathExport', () => {
  const exportsField = { './sub': './lib/parse.js' };

  it('stays import-level without symbol data and blocks an unexported subpath only with phase 233', () => {
    expect(subpathExport(false, exportsField, 'pkg/missing', 'lib/parse.js', true).kind).toBe('import');
    expect(subpathExport(true, exportsField, 'pkg/sub', undefined, true).kind).toBe('import');
    expect(subpathExport(true, exportsField, 'pkg/sub', 'lib/parse.js', false)).toMatchObject({
      kind: 'symbol',
      target: './lib/parse.js',
    });
    expect(subpathExport(true, exportsField, 'pkg/missing', undefined, true).kind).toBe('not-a-reach');
    expect(subpathExport(true, exportsField, 'pkg/missing', undefined, false).kind).toBe('import');
  });
});

describe('phase 238 tryRequireEvidence', () => {
  it('keeps the require imported and sets optionalImport only inside try when both flags are on', () => {
    const inside = 'try {\n  require(\'optional-pkg\');\n} catch (err) {}\n';
    const outside = 'require(\'optional-pkg\');\n';
    expect(tryRequireEvidence(false, false, inside)[0]).toEqual({ name: 'optional-pkg', line: 2, imported: true });
    expect(tryRequireEvidence(true, true, inside)[0]?.optionalImport).toBe(true);
    expect(tryRequireEvidence(true, false, inside)[0]?.optionalImport).toBeUndefined();
    expect(tryRequireEvidence(true, true, outside)[0]?.optionalImport).toBeUndefined();
  });
});

describe('phase 239 reexportSpec', () => {
  it('counts value re-exports up to depth 5 and skips export type', () => {
    expect(reexportSpec(false, "export * from 'pkg'")[0]?.countsAsImport).toBe(false);
    expect(reexportSpec(true, "export * from 'pkg'; export { x } from 'pkg'").every((hit) => hit.countsAsImport)).toBe(
      true,
    );
    expect(reexportSpec(true, "export type { x } from 'pkg'")[0]).toMatchObject({ countsAsImport: false, typeOnly: true });
    expect(reexportSpec(true, "export * from 'pkg'", 5)[0]?.countsAsImport).toBe(true);
    expect(reexportSpec(true, "export * from 'pkg'", 6)[0]?.countsAsImport).toBe(false);
  });
});

describe('phase 240 typeOnlyImport', () => {
  it('drops import type only when the flag is on and keeps a value import', () => {
    expect(typeOnlyImport(false, "import type { X } from 'pkg'")[0]?.countsAsImport).toBe(true);
    expect(typeOnlyImport(true, "import type { X } from 'pkg'")[0]?.countsAsImport).toBe(false);
    expect(typeOnlyImport(true, "export type { X } from 'pkg'")[0]?.countsAsImport).toBe(false);
    expect(typeOnlyImport(true, "import { x } from 'pkg'")[0]).toMatchObject({ countsAsImport: true, typeOnly: false });
    const mixed = "import type { X } from 'pkg';\nimport { x } from 'pkg';";
    const hits = typeOnlyImport(true, mixed);
    expect(hits.some((hit) => hit.typeOnly === false && hit.countsAsImport)).toBe(true);
  });
});

describe('phase 229 optional edge', () => {
  it('names a missing optional package and skips one that is installed', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_OPTIONAL = '1';
    const missing = await laneFindings(input('app', { lockTexts: { 'package-lock.json': lockOptional(false) } }));
    expect(missing.map((finding) => finding.ruleId)).toEqual(['DEPS-GRAPH-OPTIONAL-001']);
    expect(missing[0]).toMatchObject({ severity: 'info', snippet: 'fsevents' });
    expect(missing[0]?.reachability).toBeUndefined();
    const present = await laneFindings(input('app', { lockTexts: { 'package-lock.json': lockOptional(true) } }));
    expect(present).toEqual([]);
  });
});

describe('phase 230 peer edge', () => {
  it('flags a missing non-optional peer and ignores optional or present peers', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_PEER = '1';
    const findings = await laneFindings(input('app', { lockTexts: { 'package-lock.json': lockPeers() } }));
    expect(findings.map((finding) => finding.snippet)).toEqual(['missing-peer']);
    expect(findings[0]?.severity).toBe('medium');
  });
});

describe('phase 231 alias edge', () => {
  it('records alias to target and ignores a normal dependency', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_ALIAS = '1';
    const aliased = await laneFindings(input('app', {
      manifestRaw: JSON.stringify({ dependencies: { 'my-lodash': 'npm:lodash@4.17.21' } }),
      lockTexts: { 'package-lock.json': '{"packages":{"":{}}}' },
    }));
    expect(aliased[0]).toMatchObject({ ruleId: 'DEPS-GRAPH-ALIAS-001', severity: 'info', snippet: 'my-lodash → lodash' });
    const plain = await laneFindings(input('app', {
      manifestRaw: JSON.stringify({ dependencies: { lodash: '^4.17.21' } }),
      lockTexts: { 'package-lock.json': '{"packages":{"":{}}}' },
    }));
    expect(plain).toEqual([]);
  });
});

describe('phase 241 dual package', () => {
  it('flags a CJS require of an ESM-only package and skips a require condition, an import, and no packument', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_DUALPACKAGE = '1';
    const cwd = await tempDir();
    await mkdir(join(cwd, 'node_modules', 'esm-only'), { recursive: true });
    await mkdir(join(cwd, 'node_modules', 'dual'), { recursive: true });
    await writeFile(join(cwd, 'node_modules', 'esm-only', 'package.json'), JSON.stringify({
      type: 'module',
      exports: { '.': { import: './index.js' } },
    }));
    await writeFile(join(cwd, 'node_modules', 'dual', 'package.json'), JSON.stringify({
      type: 'module',
      exports: { '.': { import: './index.js', require: './index.cjs' } },
    }));
    await writeFile(join(cwd, 'app.js'), "require('esm-only');\nrequire('dual');\nrequire('unknown');\n");
    await writeFile(join(cwd, 'mod.js'), "import esmOnly from 'esm-only';\n");
    const findings = await laneFindings(input(cwd, { files: ['app.js', 'mod.js'] }));
    expect(findings.map((finding) => `${finding.ruleId}:${finding.snippet}`)).toEqual(['DEPS-DUALPACKAGE-001:esm-only']);
    expect(findings[0]?.severity).toBe('medium');
  });
});

describe('phase 242 phantom deep', () => {
  it('reports an undeclared literal dynamic import and skips a declared name and a non-literal', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_PHANTOM_DEEP = '1';
    const cwd = await tempDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { express: '^4.0.0' } }));
    await writeFile(join(cwd, 'app.js'), "import('missing-pkg');\nimport('express');\nimport(name);\nrequire.resolve('also-missing');\n");
    const manifest = await readFile(join(cwd, 'package.json'), 'utf8');
    const findings = await laneFindings(input(cwd, { files: ['app.js'], manifestRaw: manifest }));
    expect(findings.map((finding) => finding.snippet).sort()).toEqual(['also-missing', 'missing-pkg']);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-PHANTOM-002' && finding.severity === 'medium')).toBe(true);
  });
});

describe('flags off and clean-app', () => {
  it('emits nothing when flags are off', async () => {
    const findings = await laneFindings(input('app', { lockTexts: { 'package-lock.json': lockOptional(false) } }));
    expect(findings).toEqual([]);
  });

  it('emits none of the new rule ids on clean-app with flags on', async () => {
    for (const flag of FLAGS) {process.env[flag] = '1';}
    const lockText = await readFile(join(cleanApp, 'package-lock.json'), 'utf8');
    const lock = JSON.parse(lockText) as { packages: Record<string, { peerDependencies?: Record<string, string> }> };
    expect(lock.packages['node_modules/express']).toBeDefined();
    expect(lock.packages['node_modules/express-rate-limit']?.peerDependencies?.express).toBeDefined();
    const files = await walkFiles({ cwd: cleanApp });
    const manifestRaw = await readFile(join(cleanApp, 'package.json'), 'utf8');
    const findings = await laneFindings(input(cleanApp, {
      files,
      manifestRaw,
      lockTexts: { 'package-lock.json': lockText },
      cacheDir: join(cleanApp, 'missing-cache'),
    }));
    expect(findings.filter((finding) => (RULE_IDS as readonly string[]).includes(finding.ruleId))).toEqual([]);
  });
});

function lockOptional(present: boolean): string {
  const packages: Record<string, unknown> = {
    '': { optionalDependencies: { fsevents: '^2.3.2' } },
    'node_modules/parent': { optionalDependencies: { fsevents: '^2.3.2' } },
  };
  if (present) {packages['node_modules/fsevents'] = { version: '2.3.3', optional: true };}
  return JSON.stringify({ packages });
}

function lockPeers(): string {
  return JSON.stringify({
    packages: {
      '': {},
      'node_modules/express': { version: '4.21.0' },
      'node_modules/with-optional': {
        peerDependencies: { express: '>=4', 'optional-peer': '1' },
        peerDependenciesMeta: { express: { optional: true }, 'optional-peer': { optional: true } },
      },
      'node_modules/with-required': {
        peerDependencies: { express: '>=4', 'missing-peer': '1' },
      },
    },
  });
}
